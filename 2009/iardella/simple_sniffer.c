#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pcap.h>
#include <pwd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>

#include "simple_sniffer.h"

/* 
   @author: iardella
*/
pcap_t *handle;

int igmpPkts, icmpPkts, udpPkts, tcpPkts, unknownPkts, rrdUpdates, toDB = 0;

struct passwd *rootPwd;

struct timeval *start;
struct timeval *stop;

int rrdstep = 60;
char *create = "rrdtool create packets.rrd --step 60 DS:packets:COUNTER:90:U:U RRA:AVERAGE:0.5:2:10";
char *update = "rrdtool update packets.rrd N:%ld";
char *graph = "rrdtool graph packets.png --start end-30m DEF:receivedPackets=packets.rrd:packets:AVERAGE LINE1:receivedPackets#0000FF";

int datalink;

/* ************************************* */

/* Display help */
static void help() {
  printf("simple_sniffer -f|-i <file>.pcap|device \n");
  printf("This tool reads packets from a .pcap file or from an interface and prints info about packages\n");
  printf("Example: simple_sniffer -f ppp.cap");
}

/* ************************************* */

/* Callback function invoked in the listening loop */
void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
  /* TODO: modificare chiamate di sistema rrdtool... */
  
  int offset = 0, hlen;
  struct ether_header ehdr;
  struct ip ip;
  u_short eth_type;

  /*
    printf("processPacket(p_len=%d, datalink=%d)\n", header->len, datalink);
  */

  if(datalink == DLT_EN10MB) /* Ethernet */
    {
      offset = 0;
    } 
  else if (datalink == 113 /* Linux cooked */) 
    {
      offset = 16;
    }

  hlen = offset;

  if(datalink == 113 /* Linux cooked */) 
    {
      eth_type = ETHERTYPE_IP;
    } 
  else 
    {
      /*hlen = 0 se si tratta di un pacchetto ethernet*/
      memcpy(&ehdr, packet + hlen, sizeof(struct ether_header));
      
      hlen += ETHERNET_SIZE;

      eth_type = ntohs(ehdr.ether_type);
      
      if(hlen >= header->caplen) 
	return; /* Pkt too short */
  }

  if(eth_type == ETHERTYPE_IP /* IP protocol */) 
    { 
      memcpy(&ip, packet + hlen, sizeof(struct ip));
       
      /*Consideriamo solo ipV4*/
      if(ip.ip_v != 4) 
	{
	  printf("SimpleSniffer> this is not an IPv4 packet\n");
	  return;
	}

    
      
      /* Running as non root */
	
      hlen += ((u_int)ip.ip_hl * 4);
      
      if(hlen >= header->caplen) return; /* Pkt too short */

      long int epochS = header->ts.tv_sec + (header->ts.tv_usec / 1000000);
    
      /* Timestamp */
      printf("Received at: %s", ctime((const time_t*) &epochS));

      /* Lunghezza della porzione di pacchetto catturata */
      printf("Captured packet bytes: %d\n", header->caplen); 

      /*Ethernet source*/
      //printf("Ethernet source: %s\n", ether_ntoa((struct ether_addr*) ehdr.ether_shost));

      /* Indirizzi IP sorgente e destinazione */
      char source[INET_ADDRSTRLEN];
      char dest[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &ip.ip_src.s_addr, source, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &ip.ip_dst.s_addr, dest, INET_ADDRSTRLEN);

      /* Protocollo di trasporto */
      char *protocol = NULL;
 
      struct udphdr *udpH = NULL;
      struct tcphdr *tcpH = NULL;

      if (ip.ip_p == 1)
	{
	  protocol = "ICMP";
	  icmpPkts++;
	}

      if (ip.ip_p == 2)
	{
	  protocol = "IGMP";
	  igmpPkts++;
	}

      if (ip.ip_p == 17)
	{
	  udpH = malloc(sizeof(struct udphdr));
	  memcpy(udpH, packet + hlen, sizeof(struct udphdr));
	  protocol = "UDP";
	  udpPkts++;
	}
      
      if (ip.ip_p == 6)
	{
	  tcpH = malloc(sizeof(struct tcphdr));
	  memcpy(tcpH, packet + hlen, sizeof(struct tcphdr));
	  protocol = "TCP";
	  tcpPkts++;
	}

      if (protocol != NULL)
	printf("Packet protocol: %s\n", protocol);
      else
	unknownPkts++;

      
      /* Stampa <indirizzo:porta> sorgente e <indirizzo:porta> destinazione */
      if (udpH != NULL)
	{
	  printf("UDP source: %s:%d\n", source, ntohs(udpH->source));
	  printf("UDP destination: %s:%d\n", dest, ntohs(udpH->dest));
	}
      else
	{
	  if (tcpH != NULL)
	    {
	      printf("TCP source: %s:%d\n", source, ntohs(tcpH->source));
	      printf("TCP destination: %s:%d\n", dest, ntohs(tcpH->dest));
	    }
	}

      printf("\n");
    }
}

/* ************************************* */

/* MAIN */
int main(int argc, char* argv[]) 
{
  /* Input check */

  char *device = NULL;
  char errbuf[256];
  
  if(argc < 3) 
    {
      help();
      return(0);
    }
  else
    device = argv[2];
  
  /* ***************************** */
  
  /* Signals management */

  struct sigaction *old1 = (struct sigaction *) malloc (sizeof(struct sigaction));
  struct sigaction *new1 = (struct sigaction *) malloc (sizeof(struct sigaction));
  struct sigaction *old2 = (struct sigaction *) malloc (sizeof(struct sigaction));
  struct sigaction *new2 = (struct sigaction *) malloc (sizeof(struct sigaction));
  
  new1->sa_handler = end_handler;
  sigemptyset(&new1->sa_mask);
  new1->sa_flags = 0;
  
  new2->sa_handler = alarm_handler;
  sigemptyset(&new2->sa_mask);
  new2->sa_flags = 0;
  
  /* Saving default handler1 */
  if (sigaction(SIGINT, NULL, old1) == 0)
    { /* Setting custom handler */
      if (sigaction(SIGINT, new1, NULL) < 0)
	fprintf(stderr, "SimpleSniffer> error setting SIGINT handler\n");
    }
  else
    fprintf(stderr, "SimpleSniffer> error saving default SIGINT handler\n");
  
  /* Saving default handler2 */
  if (sigaction(SIGALRM, NULL, old2) == 0)
    {
      if (sigaction(SIGALRM, new2, NULL) < 0)
	fprintf(stderr, "SimpleSniffer> error setting SIGARLM handler\n");
    }
  else
    fprintf(stderr, "SimpleSniffer> error saving default SIGARLM handler\n");
  
  /* ***************************** */

  /* Running as root */

  if (strcmp(argv[1],"-i") == 0) /* Live mode */
    {
      handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
      
      if(handle == NULL) 
	{
	  printf("pcap_open_live: %s\n", errbuf);
	  return(-1);
	}
    }
  else /* Offline mode */
    handle = pcap_open_offline(device, errbuf);
  
  /* ****************************** */
  
  if (handle == NULL)
    {
      printf("SimpleSniffer> unable to open file/device: %s\n", errbuf);
      return(-1);
    }
	
  /* Creazione RRD */
  if (system(create) == 0)
    {
      printf("SimpleSniffer> RRD created\n");
      toDB = 1;
      /* Alarm per update dell'RRD */
      alarm(rrdstep);
    }
  else
    printf("SimpleSniffer> unable to create a RRD\n");

  rootPwd = getpwnam("root");
  
  if (becomeNobody())
    printf("SimpleSniffer> running as nobody\n");
  else
    printf("SimpleSniffer> unable to become nobody\n");
  
  datalink = pcap_datalink(handle);

  start = (struct timeval *) malloc (sizeof(struct timeval));
  stop = (struct timeval *) malloc (sizeof(struct timeval));
  
  gettimeofday(start, NULL);
  
  /* Loop */
  pcap_loop(handle, -1, processPacket, NULL); /* <<-------- */
  /* ******************************** */
  
  /* TODO (?) - Restoring alarms... */
  
  return(0);
}

/* Routine to become "normal" user */
int becomeNobody()
{
  int v = 0;
  
  struct passwd *pwd = NULL;

  if (getuid() == 0)
    {
      char *user = "nobody";

      pwd = getpwnam(user);

      if (pwd != NULL)

	{
	  if ((setgid(pwd->pw_gid) == 0) || (setuid(pwd->pw_uid) == 0))
	    v = 1;
	}
    }
  
  return v;

}

/* Routine to become root */
int becomeRoot()
{
  int v = 0;
  
  if (getuid() == 0)
    return 1;
  
  if (rootPwd != NULL)
    {
      if ((setgid(rootPwd->pw_gid) == 0) && (setuid(rootPwd->pw_uid) == 0))
	v = 1;
      
    }
  
  return v;
}

/* SIGINT signal handler */
void end_handler(int signum)
{
  gettimeofday(stop, NULL);
  
  printReport();
  
  if (handle != NULL)
    pcap_close(handle);
  
  exit(0);
}

/* SIGALRM signal handler */
void alarm_handler(int signum)
{
  printf("SimpleSniffer> updating rrd...\n");
  
  if (toDB)
    {
      char *updateString = (char*) malloc(sizeof(char) * strlen(update) + sizeof(long int));
      
      if (sprintf(updateString, update, (igmpPkts + icmpPkts + udpPkts + tcpPkts + unknownPkts)) > 0) 
	{  
	  if (becomeRoot())
	    {
	      if (system(updateString) == 0)
		{
		  printf("SimpleSniffer> RRD updated\n");
		  rrdUpdates++;
		}
	      else
		
		printf("SimpleSniffer> error updating RRD\n");
	      
	      
	      if (!becomeNobody())
		printf("SimpleSniffer> warning: unable to become nobody; running as root, again !\n");
	    }
	  else
	    printf("SimpleSniffer> unable to update RRD\n");
	  
	  /* Attivazione allarme per il prossimo update */
	  alarm(rrdstep);
	}
      
      if (updateString != NULL)
	free(updateString);
    }
}

/* Report routine */
void printReport()
{
  /* Creazione grafo, eliminazione db */
  if (toDB && system(graph) == 0)
      printf("SimpleSniffer> RRD graph created.\n");
  
  
  printf("\n");
  printf("********************************\n");
  printf("Started at     :    %s", ctime((const time_t*) &start->tv_sec));
  printf("Finished at    :    %s", ctime((const time_t*) &stop->tv_sec));
  printf("Sniffed packets:    %d\n", (igmpPkts + icmpPkts + udpPkts + tcpPkts + unknownPkts));
  printf("Writes on RRD  :    %d\n", rrdUpdates);
  printf("IGMP packets   :    %d\n", igmpPkts);
  printf("ICMP packets   :    %d\n", icmpPkts);
  printf("UDP  packtts   :    %d\n", udpPkts);
  printf("TCP  packets   :    %d\n", tcpPkts);
  printf("Not recognized :    %d\n", unknownPkts);
  printf("********************************\n");
  printf("\n");
}
	

