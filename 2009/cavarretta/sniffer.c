#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>
#include <pwd.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <rrd.h>
#include "sniffer.h"
#include "pkt_info.h"
#include "timer.h"

pcap_t *in_pcap;
u_int8_t hwAddr[ETH_ALEN];
char *rrd_create_command[RRD_CREATE_ARGC];
t_pkt_queue *queues[NUM_THREADS];
t_hashTable *flowsTable;
/* counters to be stored in RRD */
unsigned int inbound = 0;
unsigned int outbound = 0;
unsigned int promisquous = 0;

void updateCounters(const struct pcap_pkthdr *h, const struct ether_header *eth_hdr)
{
	if (memcmp(hwAddr,eth_hdr->ether_shost,ETH_ALEN))
	{
		if (memcmp(hwAddr,eth_hdr->ether_dhost,ETH_ALEN))
		{
#ifdef ELOQUENS
			printf("\tPromisquous");
#endif
			promisquous += h->len;
		}
		else
		{
#ifdef ELOQUENS
			printf("\tInbound");
#endif
			inbound += h->len;
		}
	}
	else
	{
#ifdef ELOQUENS
		printf("\tOutbound");
#endif
		outbound += h->len;
	}
}

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p)
{
	t_pkt_info pkt_info;
#ifdef ELOQUENS
	char buf[80];
#endif

	struct ether_header *eth_hdr;
	struct ip *ip;
	struct tcphdr *tcp_hdr;
	u_short eth_type;
	int hlen = 0;
	u_char *ip_payload;

	unsigned int queueNO;

	pkt_info.len = h->len;
	/* Fills the packet timestamp */
	pkt_info.capture_time = (time_t)(h->ts.tv_sec);
#ifdef ELOQUENS
	/* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
	getCaptureTime(&pkt_info,buf,sizeof(buf));
	printf("%s",buf);
#endif

	eth_hdr = (struct ether_header *)p;
	hlen += sizeof(struct ether_header);

    if(hlen >= h->caplen)
    {
#ifdef ELOQUENS
    	printf("\tPacket too short.\n");
#endif
    	return;
    }

    updateCounters(h,eth_hdr);
    eth_type = ntohs(eth_hdr->ether_type);
    if(eth_type == 0x0800 /* IP */)
    {
    	ip = (struct ip *)(p + hlen);
    	if (ip->ip_v != 4)
    	{
#ifdef ELOQUENS
    		printf("\tNot an IPv4 packet.\n");
#endif
    		return;
    	}

    	hlen += ((u_int)ip->ip_hl * 4);

    	if (hlen >= h->caplen)
    	{
#ifdef ELOQUENS
    		printf("\tPacket too short.\n");
#endif
    		return;
    	}

    	/* Prints the packet level 4 protocol */
    	pkt_info.ip_p = ip->ip_p;
    	switch(pkt_info.ip_p)
    	{
    	case IPPROTO_TCP:
    		tcp_hdr = (struct tcphdr *)(p + hlen);
#ifdef ELOQUENS
    		printf("\tProtocol: TCP");
#endif
    		hlen += sizeof(struct tcphdr);
    		if (hlen >= h->caplen)
    		{
#ifdef ELOQUENS
    			printf("\tPacket too short.\n");
#endif
    		  	return;
    		}
# ifdef __FAVOR_BSD
    		pkt_info.TCPflags = tcp_hdr->th_flags;
# else /* !__FAVOR_BSD */
    		pkt_info.res1 = tcp_hdr->res1;
    		pkt_info.doff = tcp_hdr->doff;
    		pkt_info.fin = tcp_hdr->fin;
    		pkt_info.syn = tcp_hdr->syn;
    		pkt_info.rst = tcp_hdr->rst;
    		pkt_info.psh = tcp_hdr->psh;
    		pkt_info.ack = tcp_hdr->ack;
    		pkt_info.urg = tcp_hdr->urg;
    		pkt_info.res2 = tcp_hdr->res2;
# endif /* __FAVOR_BSD */
    		hlen -= sizeof(struct tcphdr);
    		break;
#ifdef ELOQUENS
    	case IPPROTO_UDP:
    		printf("\tProtocol: UDP");
    		break;
    	case IPPROTO_ICMP:
    		printf("\tProtocol: ICMP");
    		break;
    	case IPPROTO_IP:
    		printf("\tProtocol: IP");
    		break;
    	default:
    		printf("\tProtocol: %d", ip->ip_p);
#endif
    	}

    	ip_payload = (u_char *)(p + hlen);
    	hlen += 2 * sizeof(uint16_t);

    	if (hlen >= h->caplen)
    	{
#ifdef ELOQUENS
    		printf("\tPacket too short.\n");
#endif
    	    return;
    	}

    	/* Prints the source IP and port and the destination IP and port*/
    	pkt_info.src_addr = ip->ip_src;
    	pkt_info.dst_addr = ip->ip_dst;
    	pkt_info.src_port = *(uint16_t*)ip_payload;
    	ip_payload += sizeof(uint16_t);
    	pkt_info.dst_port = *(uint16_t*)ip_payload;
#ifdef ELOQUENS
    	printf("\tFrom: %s:%u", getSrcAddr(&pkt_info), getSrcPort(&pkt_info));
    	printf("\tTo: %s:%u\n", getDstAddr(&pkt_info), getDstPort(&pkt_info));
#endif

    	/* Riconosco il flusso e lo pongo nella coda opportuna */
    	queueNO = toHash(&pkt_info) % NUM_THREADS;
    	enqueue(queues[queueNO],&pkt_info);
    }
#ifdef ELOQUENS
    else
    	printf("\tNot an IP packet.\n");
#endif
}

void getHwAddr(const char *ifName)
{
	int s;
	struct ifreq buffer;
	s = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, ifName);
	ioctl(s, SIOCGIFHWADDR, &buffer);
	close(s);
	memcpy(hwAddr,(u_int8_t *)buffer.ifr_hwaddr.sa_data,ETH_ALEN);
}

void leaveRoot()
{
	struct passwd *pw = NULL;

	if(getuid() == 0)
	{
		/* We're root */
		char *user;
		pw = getpwnam(user = "nobody");
		if(pw != NULL) {
			if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
				fprintf(stderr,"Unable to change user to %s [%d: %d]: sticking with root\n",user,pw->pw_uid,pw->pw_gid);
			else
				fprintf(stdout,"Sniffer changed user to %s\n",user);
		}
	}
}

/* this is the thread that extracts packet information from a queue it only reads from
 * and updates the flow cache*/
void *flowMgr(void *arg)
{
	t_pkt_info *pkt;
	t_pkt_queue *queue = (t_pkt_queue *)arg;
	while(1)
	{
		pkt = dequeue(queue);
		updateHashEntry(flowsTable,pkt);
	}
	return (void *) NULL;
}

int main (int argc, char *argv[])
{
	int index;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *interface;
	struct stat info;
	bool existRRD = FALSE;
	bool useRRD = TRUE;
	pthread_t timerT; /* the ID of the timer thread */
	pthread_t threads[NUM_THREADS]; /* the IDs of the threads managing flows */
	int createReturn; /* return code from rrd_create and pthread_create */
	if (argc < 3)
	{
		printf("USAGE: sniffer (-i interface | -i -list | -f filename)\n");
		return 0;
	}
	switch (argv[1][1])
	{
	case 'i':
		switch (argv[2][0])
		{
		case '-': /* The user asked for the list of available interfaces */
			if (!strcmp((argv[2] + sizeof(char)),"list"))
			{
				int result;
				int index = 0;
				int choose;
				pcap_if_t *alldevsp;
				pcap_if_t *current_int;
				/* List all available interfaces */
				result = pcap_findalldevs(&alldevsp, errbuf);
				if (result)
				{
					printf("Could not list interfaces:\n* pcap_findalldevs: %s", errbuf);
					return -1;
				}
				current_int = alldevsp;
				printf("Interfaces:\n");
				while(current_int)
				{
					printf("%d. %s: %s\n", index, current_int->name, current_int->description);
					current_int = current_int->next;
					index++;
				}
				/* Ask the user to choose an interface */
				do
				{
					char carriageReturn;
					printf("Choose an interface: (0-%d): ", index - 1);
					scanf("%d%c", &choose, &carriageReturn);
				} while (choose < 0 || choose > index - 1);
				current_int = alldevsp;
				for(index = 0; index < choose; index++)
					current_int = current_int->next;
				interface = current_int->name;
				break;
			}
			else
			{
				printf("Unrecognized option: %s;\nUSAGE: sniffer (-i interface | -i -list | -f filename)\n", argv[2]);
				return -1;
			}
		default: /* The user specified an interface to sniff from using a command line argument */
			interface = argv[2];
		}
		/* Open the specified interface for sniffing */
		printf("Sniffing on interface: %s\n", interface);
		in_pcap = pcap_open_live(interface,65535,1,1000,errbuf);
		leaveRoot();
		getHwAddr(interface);
		break;
	case 'f': /* The user asked to read packets from a specified file */
		printf("Reading packets from file: %s\n", argv[2]);
		in_pcap = pcap_open_offline(argv[2], errbuf);
		break;
	default:
		printf("Unrecognized option: %s;\nUSAGE: sniffer (-i interface | -i -list | -f filename)\n", argv[1]);
		return -1;
	}

	if(in_pcap == NULL) {
	    printf("pcap_open: %s\n", errbuf);
	    return(-1);
	}
	/* Search for the round robin database on the filesystem,
	 * if not found asks the user if he wish to create it */
	existRRD = stat("./rrd.rrd",&info);
	if (existRRD)
	{
		if (errno == ENOENT)
		{
			char answer;
			char carriageRtn;
			do
			{
				fprintf(stdout, "Sniffer: could not locate ./rrd.rrd, whould you like to create it? (y/n) ");
				scanf("%c%c",&answer,&carriageRtn);
			}
			while (answer != 'y' && answer != 'n');
			if (answer == 'y')
			{
				int index;
				useRRD = TRUE;
				rrd_create_command[0] = "create";
				rrd_create_command[1] = "rrd.rrd";
				rrd_create_command[2] = "--step";
				rrd_create_command[3] = "5";
				rrd_create_command[4] = "DS:in:COUNTER:10:U:U";
				rrd_create_command[5] = "DS:out:COUNTER:10:U:U";
				rrd_create_command[6] = "DS:pro:COUNTER:10:U:U";
				rrd_create_command[7] = "RRA:AVERAGE:0.5:1:12";
				rrd_create_command[8] = "RRA:AVERAGE:0.5:12:60";
				printf("Creating rrd with:\n");
				for (index = 0; index < RRD_CREATE_ARGC; index++)
					printf("%s ",rrd_create_command[index]);
				printf("\n");
				createReturn = rrd_create(RRD_CREATE_ARGC,rrd_create_command);
				if (createReturn)
				{
					fprintf(stderr,"ERROR: rrd_create, %s\n",rrd_get_error());
					exit(-1);
				}
				else
					printf("RRD successfully created.\n");
			}
			else
				useRRD = FALSE;
		}
		else
		{
			perror("Sniffer: couldn't access ./rrd.rrd");
			return 1;
		}
	}

	/* Creates the thread that regularly collects flows into the cemetery
	 * and updates the RRD if a round robin database was found on the filesystem
	 * or created by the user when he was asked for */
	createReturn = pthread_create(&timerT,NULL,timer,(useRRD ? &useRRD : NULL));
	if (createReturn)
	{
		printf("ERROR; return code from pthread_create() is %d\n", createReturn);
		exit(-1);
	}

	flowsTable = createHash(FLOW_TABLE_SIZE,toHash,updateFlow,printFlowID,printFlowInfo);

	/* Creates NUM_THREADS flow manager threads and the queues of packets they read from */
	for(index = 0; index < NUM_THREADS; index++)
	{
		queues[index] = createQueue(QUEUE_SIZE);
		if (!queues[index])
			exit(-1);
		createReturn = pthread_create(&threads[index],NULL,flowMgr,queues[index]);
		if (createReturn)
		{
			printf("ERROR; return code from pthread_create() is %d\n", createReturn);
			exit(-1);
		}
	}

	pcap_loop(in_pcap, -1, processPacket, NULL);
	pcap_close(in_pcap);

	printf("Done!\n");

	return 0;
}
