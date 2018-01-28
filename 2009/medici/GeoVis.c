/*
 * GeoVis.c
 *
 *  Created on: 26-mag-2009
 *      Author: Gianluca Medici
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

#include "sysmacro.h"
#include "GeoVis.h"
#include "myhash.h"
#include "webStuff.h"
#include "analyzer.h"

#define MAXSNAPLEN					36			//size in bytes of the max portion of the packets considered by pcap
#define DEFAULT_PROTOCOL			0
#define PATH_GEOIP_DB		"/usr/local/share/GeoIP/GeoIP.dat"
#define PATH_GEOIP_DBCITY   "/usr/local/share/GeoIP/GeoLiteCity.dat"
#define CONSIDER_IP_SRC			   -1
#define CONSIDER_IP_DST			0
#define CONSIDER_IP_SRC_AND_DST 	1

//GeoIP * gi;			   						//Global pointer at the GeoIp opened database
GeoIP *giCitta;		   							//Global pointer at the GeoLite City opened database

extern int datalink;

/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
static int startup(int port){
	int serverFd;							/*Server Socket*/
	struct sockaddr_in serverINETAddress;	/*Server Internet Address*/
	struct sockaddr* serverSockAddrPtr;		/*Pointer to server address*/

	int serverLen, rc;
	int sockopt = 1;

	serverFd = socket(AF_INET, SOCK_STREAM, DEFAULT_PROTOCOL);
	IFERROR(serverFd, "socket Error");

	serverLen=sizeof(serverINETAddress);
	bzero((char*) &serverINETAddress, serverLen);
	serverINETAddress.sin_family=AF_INET;
	serverINETAddress.sin_addr.s_addr=htonl(INADDR_ANY);	/*accept all*/
	serverINETAddress.sin_port=htons(port);					/*Server port number*/
	serverSockAddrPtr= (struct sockaddr*) &serverINETAddress;

	rc = setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
	if((rc < 0) || (errno != 0)) {
		perror("Unable to set socket options ");
		exit(38); /* Just in case */
	}


	IFERROR(bind(serverFd, serverSockAddrPtr, serverLen), "bind error");
	IFERROR(listen(serverFd, 5) ,"listen error");


	return(serverFd);
}


static int get_line(int sock, char *buf, int size)
{
 int i = 0;
 char c = '\0';
 int n;

 while ((i < size - 1) && (c != '\n'))
 {
  n = recv(sock, &c, 1, 0);
  /* DEBUG printf("%02X\n", c); */
  if (n > 0)
  {
   if (c == '\r')
   {
    n = recv(sock, &c, 1, MSG_PEEK);
    /* DEBUG printf("%02X\n", c); */
    if ((n > 0) && (c == '\n'))
     recv(sock, &c, 1, 0);
    else
     c = '\n';
   }
   buf[i] = c;
   i++;
  }
  else
   c = '\n';
 }
 buf[i] = '\0';

 return(i);
}



int main(int argc, char *argv[]) {
	struct sockaddr_in clientINETAddress;		/*Client internet Address*/
	struct sockaddr* clientSockAddrPtr;			/*Pointer to client address*/
	char buf[1024];
	int k, clientLen;
	struct bpf_program fp;						/* The compiled filter expression */
	char filter_exp[] = "ip";					/* The filter expression to get just ip//( ppp[2:2] & 0xffff = 0x0021 or ip )  and not dst net 192.168  ip  0xffff =  and host//   */
	char *geoIpDatabase=PATH_GEOIP_DBCITY;		/* Default location of the GeoIp city lite database */
	char errbuf[PCAP_ERRBUF_SIZE];				/* Error string */
	int server_sock = 	-1;
	int client_sock = 	-1;
	int selec =			CONSIDER_IP_SRC;
	int numPackets = 	0;
	pcap_t* captured= NULL;
	char opzioni[] = "p:a:g:";					/*accepted options, for getopt*/

	/*Parse the argument passed on the command line*/
	k = getopt(argc, argv, opzioni);

	/*if there are no arguments passed print the use message*/
	if (k == -1) {
		printf("\nGeoPacketVisualizer's options are:\n\n");
		printf( "-p <name_pcapfile>		pcap save file with the packets to analyze\n\n");

		printf(
				"-a (all | scr | dst)		Choose if the analysis has to be based on dst ip and src ip (all)\n\t\t\t\ton the source ip only (src DEFAULT)\n\t\t\t\tor on the destination ip only (dst)\n\n");

		printf( "-g <GeoCity lite DB file>	Set the location of the database GeoLite City(default %s)\n\n", PATH_GEOIP_DBCITY);
		return 0;
	}
	printf("\n****Starting GeoPacketVisualizer****\n\n");

	do {

		switch (k) {

		case 'p': {
			captured = pcap_open_offline(optarg, errbuf);
			if(captured == NULL){
				fprintf(stderr, "Error opening pcap savefile: %s", errbuf);
				exit(1);
			}

			pcap_set_snaplen(captured, MAXSNAPLEN); //catturo solo i primi MAXSNAPLEN byte (Ethernet+ip)
			printf("The packets captured are truncated after %d bytes\n",
					MAXSNAPLEN);

			if (pcap_compile(captured, &fp, filter_exp, 0, 0) == -1) {
				fprintf(stderr, "Couldn't parse filter %s\n", pcap_geterr(
						captured));
				exit(1);
			}

			IFERROR(pcap_setfilter(captured, &fp), "Couldn't install filter");
			printf("The filter installed will capture datagram wrapping ip\n");


			datalink = pcap_datalink(captured);

			break;
		}

		case 'a': {
			if (strcmp(optarg, "all") == 0) {
				selec = CONSIDER_IP_SRC_AND_DST;
				printf("The ips considered for analysis will be from SRC and DST field\n");
				break;
			}
			if (strcmp(optarg, "dst") == 0) {
				selec = CONSIDER_IP_DST;
				printf("The ips considered for analysis will be from DST field only\n");
				break;
			}
			if (strcmp(optarg, "src") == 0) {
				selec = CONSIDER_IP_SRC;
				printf("The ips considered for analysis will be from SRC field only\n");
				break;
			}else{

			}
			break;
		}

		case 'g': {
			geoIpDatabase=optarg;
			break;
		}

		case '?': {
			printf("\nGeoPacketVisualizer's options are:\n\n");
			printf(
					"-p <name_pcapfile>		pcap save file with the packets to analyze\n\n");
			printf(
					"-a (all | scr | dst)		Choose if the analysis has to be based on dst ip and src ip (all)\n\t\t\t\ton the source ip only (src DEFAULT)\n\t\t\t\tor on the destination ip only (dst)\n\n");

			printf("-g <GeoCity lite DB file>	Set the location of the database GeoLite City(default %s)\n\n", PATH_GEOIP_DBCITY);
			exit(0);
			break;
		}
		}
		k = getopt(argc, argv, opzioni);
	} while (k != -1);

	if(captured == NULL){
		fprintf(stderr, "No pcap savefile passed, use the option -p!\n");
		exit(1);
	}


	//load the database GeoLite city in memory
	giCitta = GeoIP_open(geoIpDatabase, GEOIP_MEMORY_CACHE);
	if (giCitta == NULL) {
		perror("Error opening database\n");
		exit(1);
	} else {
		printf("Successfully opened GeoLite City database! Location %s\n\n",
				geoIpDatabase);
	}

	/* selec is the variable use to choose if consider src, dst or src and dst
	 * of the ip addresses found in the packets*/
	numPackets = pcap_dispatch(captured, -1, (pcap_handler) processPacket,
			(u_char*) &selec);

	if (numPackets == -1) {
		pcap_perror(captured,
				"Error while processing offline capture packets!\n");
		exit(1);
	}

	if (numPackets == -2) {
		fprintf(stderr,
				"Breakloop while processing packets, impossible to continue!\n");
		exit(1);
	}
	printf("****Analyzing packets****\n\n");

	printf("	%d packets were successfully processed!\n", PKTprocessed);

	if (PKToutsideBuckett > 0) {
		printf("%d packets were dropped due to not implemented protocol\n",
				PKToutsideBuckett);
	}

	printf("	The analysis showed packets coming from %d nations\n",
			countNations(&IpHastTable));
	//print_nations();
	//print_nationsAndCity();
	printf("	Total ip considered for analysis %d\n", totalIpConsidered);

	printf("	Number of packet from unidentified countries %d\n",
			PKTfromUnidentifiedCountry);
	printf("	Number of packet from unidentified cities %d\n\n", PKTfromUnknowCity);
	server_sock = startup(BROWSER_PORT);

	printf("GeoPacketVisualizer is running on port %d\n\n", BROWSER_PORT);

	printf("To see the result of the analysis open your favorite browser on:\n");
	printf("http://localhost:%d\n\n", BROWSER_PORT);
	printf("Remember to activate the scripts and to be connected on the Internet!\n<Have fun!>\n");
	fflush(stdout);

	clientLen = sizeof(clientINETAddress);
	clientSockAddrPtr = (struct sockaddr*) &clientINETAddress;
	//while(1){
	client_sock = accept(server_sock, clientSockAddrPtr,
			(socklen_t*) &clientLen);
	IFERROR(client_sock ,"accept error");

	/*gets a line of text sended by a client(browser), assume it is a GET message*/
	get_line(client_sock, buf, sizeof(buf));

	//printf("Dati %d\n", numchars);
	//printf("MSG %s", buf);

	sendChartPage(client_sock);

	shutdown(client_sock, 1);
	//}


	/* Remove the hash structure used to collect info
	 * on the ip addresses and free the memory space allocated*/
	delete_all(&IpHastTable);

	closeSocket(&client_sock);
	closeSocket(&server_sock);
	printf("****Closing GeoPacketVisualizer****\n\n");
	printf("****Successful Termination****\n\n");
	fflush(stdout);
	return 0;
}

