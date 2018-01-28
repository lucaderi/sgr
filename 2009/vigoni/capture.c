/*
 * capture.c
 *
 *  Created on: 01-ott-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "capture.h"
#include "rrd.h"
#include "cbuffer.h"
#include "hashtable.h"
#include "HTTPinterface.h"

/*** Global Vars ******************************************************************** ***/
/************************************************************************************ ***/

struct passwd * last_pw;	/* password */

int verbose = 0;	        /* verbose global var */
int print = 0;		        /* print all packets global var */
int enable_rrd = 0;			/* enable rrdtool */

int end = 0;		        /* end global var */

int secs = 0;				/* secs counter */

/*** Packet Counters ***/
u_int count = 0;			/* number of incoming packets */
u_int tcp_count= 0;			/* number of tcp packets */
u_int udp_count = 0;		/* number of udp packets */
u_int other_count = 0;		/* number of other packets */
u_int eth_count = 0;		/* number of ethernet packets */
u_int not_eth_count = 0;	/* number of non-ethernet packets */

u_int discarded = 0;		/* number of discarded packets */

/*** Bandwidth Counter ***/
u_int tcp_size = 0;			/* number of tcp incoming bytes */
u_int udp_size = 0;			/* number of udp incoming bytes */

/*** Flows Counters ***/
u_int flows = 0;			/* number of incoming flows */
u_int flows_err = 0;        /* number of errors */
u_int active_flows = 0;		/* number of active flows */
u_int ended_flows = 0;		/* number of expired flows */

/*** Global data sructure *********************************************************** ***/
/************************************************************************************ ***/

/*** Buffers for incoming packets ***/
struct cbuffer *buffers[BUFFER_NUM];		

/*** Arguments for store_routine(void*) ***/
struct store_routine_args
{
	struct cbuffer* buffer;
};

/*** Data Structure for flows ***/
HASHTABLE* db;

/*** Queue for node expire in flows data structure ***/
struct dead_node *dead_queue;

/*** Aux Functions Declarations ***************************************************** ***/
/************************************************************************************ ***/

/* Print the current version */
void print_version();

/* Switch the current user to nobody */
void change_user();

/* Print help */
static void help();

/* Start the capture routine (pcap_loop) */
static void* capture_routine(void* arg);

/* Handler per SIGALR */
void alarm_handler(int signum);

/* Handler for SIGINT */
void term_handler(int signum);

/* Print counters on the standard output */
void print_counters();

/* Print the packet p */
void print_packet(packet_t* pkt);

/* Start a new store-thread for storing flows */
void* store_routine(void* arg);

/* Start a new killer-thread for deleting the expired node in the dead_queue */
void* killer_routine(void* arg);

/* Start a new dead-thread for check the expire node in the HASHTABLE.
 * If a node (flow) is expire, this thread push it in the dead_queue. */
void* dead_routine(void* arg);

/*** ******************************************************************************** ***/
/*** ******************************* MAIN ******************************************* ***/
/*** ******************************************************************************** ***/

#ifndef HTTPD

int main(int argc, char* argv[])
{
	char *in_file = NULL;	/* name of the input file */
	char *in_device = NULL;	/* name of the input device */
	char c;					/* command option aux var */
	int i;
	int e;

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *in_pcap;					/* pcap_t */

	/*************************** Signals ***************************/
	struct sigaction salrm;	/* for alarm signal */
	struct sigaction sterm;	/* for term signal */
	/***************************************************************/

	/*************************** Threads ***************************/
	pthread_t capth;					/* for packets capturing */
	pthread_t *store_th[BUFFER_NUM];	/* for flows storing */
	pthread_t killerth;					/* for HASHTABLE cleaning */
	pthread_t deadtr;					/* for dead_queue cleaning */
	struct MHD_Daemon *http_daemon;		/* httpd for output */
	/***************************************************************/

	struct store_routine_args* str_args[BUFFER_NUM];   /* store routine threads args */

	/*** HASHTABLE init ***/
	db = hashtable_init(100);
	if(verbose) printf(">>>> hashtable init success\n");

	print_version();

	/*** parsing user option ***/
	while((c = getopt(argc, argv, "hvpri:d:")) != -1)
	{
		switch(c)
		{
		case 'v':
			verbose = 1;
			break;
		case 'p':
			print = 1;
			break;
		case 'i':
			in_file = strdup(optarg);
			break;
		case 'd':
			in_device = strdup(optarg);
			break;
		case 'h':
			help();
			break;
		case 'r':
			enable_rrd = 1;
			break;
		case '?':
			help();
		}
	}

	if(in_file != NULL)	/*** Open the input file (in_file) ***/
	{
		in_pcap = pcap_open_offline(in_file, errbuf);
		if(verbose) printf(">>>> capturing packets from file\n");
	}
	else /*** Open the input device (in_device) ***/
	{
		in_pcap = pcap_open_live(in_device, 65000, 1, 0, errbuf);

		if(enable_rrd) /*** RRDTool init ***/
		{
			if(verbose) printf(">>>> creating RRD file\n");
			rrdcreate();
			printf(">>>> RRD init success\n");
		}

		change_user();	/*** switch 'root' to 'nobody' ***/

		if(verbose && in_device == NULL) printf(">>>> capturing packets from all device\n");
		if(verbose && in_device != NULL) printf(">>>> capturing packets from device %s\n", 
				in_device);
	}

	/*** Buffers initializzation ***/
	for(i=0; i<BUFFER_NUM; i++)
	{
		str_args[i] = malloc(sizeof(struct store_routine_args));

		buffers[i] = cbuffer_init();
		if(verbose) printf(">>>> buffer[%d] init success (size: %d)\n", i, buffers[i]->size);

		str_args[i]->buffer = buffers[i];
		store_th[i] = malloc(sizeof(pthread_t));	/* store thread mem allocation */

		/* store thread start */
		if( pthread_create(store_th[i], NULL, store_routine,  str_args[i]) != 0 )
		{
			printf("ERR> can't create the thread for the packet capture\n");
			exit(0);
		}
	}
	if(verbose) printf(">>>> buffers init success\n");

	/*** pcap_open_* faliure ***/
	if(in_pcap == NULL) {
		printf("ERR> pcap_open: %s\n", errbuf);
		return(-1);
	}

	/*** THREADS ***/

	/* http daemon */
	http_daemon = httpd_init(19999);

	/* Packet-capture thread */
	if(pthread_create(&capth, NULL, capture_routine, (void*) in_pcap) != 0)
	{
		printf("ERR> can't create the thread for the packet capture\n");
		exit(0);
	}

	/* Killer thread */
	if(pthread_create(&killerth, NULL, killer_routine, NULL) != 0)
	{
		printf("ERR> can't create the thread killer\n");
		exit(0);
	}

	/* Thread for dead_queue */
	if(pthread_create(&deadtr, NULL, dead_routine, (void*) &killerth) != 0)
	{
		printf("ERR> can't create the thread for dead_queue\n");
		exit(0);
	}

	/*** SIGNALS ***/

	/* Alarm Handler */
	if(enable_rrd)
	{
		bzero(&salrm, sizeof(salrm));
		salrm.sa_handler=alarm_handler;
		sigaction(SIGALRM, &salrm, NULL);
		alarm(STEP);
	}

	/* Term Handler */
	bzero(&sterm, sizeof(sterm));
	sterm.sa_handler=term_handler;
	sigaction(SIGINT, &sterm, NULL);

	/*** Waiting the end... ***/
	while(!end)
		sleep(10);

	/*** Threads killing ***/

	/* Capture Thread */
	e = pthread_kill(capth, SIGINT);
	if(e == 0)
		printf(">>>> capture thread stopped\n");
	else
		printf("WAR> cannot stop capture thread (Error %d)\n", e);

	/*** Print result on standard output ***/
	if(verbose) printf(">>>> Print counters...\n"); 
	print_counters();

	if(enable_rrd)
	{
		if(verbose) printf("\n>>>> Saving graphs...\n");
		rrdsave();
	}

	printf("\n<<<< Exit now!\n");
	return 1;
}

#endif

/*** ******************************************************************************** ***/
/*** ***************************** END MAIN ***************************************** ***/
/*** ******************************************************************************** ***/

/*** System Functions Definitions *************************************************** ***/
/************************************************************************************ ***/

/* Print the current version */
void print_version()
{
	printf(">>>> Capture %s - A Tool for the Network Monitoring\n", VERSION);
	printf(">>>> Developed by Matteo Vigoni <mattevigo@gmail.com>\n\n");
}

/* Switch the current user to nobody */
void change_user()
{
	struct passwd *pw = NULL;
	struct passwd *current_pw = getpwuid(getuid());

	/* printf("Changing user UID:%d\n", getuid()); */
	if (getuid()==0)
	{
		char *user;
		pw = getpwnam(user ="nobody");
		if (pw!=NULL)
		{
			if((setgid(pw->pw_gid)!=0)||(setuid(pw->pw_uid)!=0))
				printf("WRN> unable to change user to %s [%d: %d]\n", 
						user, pw->pw_uid, pw->pw_gid);
			else
				printf(">>>> user changed to '%s'\n\n",user);

			last_pw = current_pw;
		}
	}
	else
	{
		if(verbose) printf("\n>>>> i'm not root, try to change user...\n\n");
		if(last_pw != NULL)
		{
			if((setgid(last_pw->pw_gid) != 0) || (setuid(last_pw->pw_uid) != 0))
				printf("WRN> unable to change user to %s [%d: %d]\n", 
						last_pw->pw_name, last_pw->pw_uid, last_pw->pw_gid);
			else
				printf(">>>> user changed to '%s'\n\n", last_pw->pw_name);
		}
	}
}

/* Print help */
static void help()
{
	printf("capture [-v] [-i <file>.pcap] [-d <device>] [-r] \n");
	printf("         -v               | Verbose\n");
	printf("         -p               | Print captured packets\n");
	printf("         -i <file>.pcap   | Pcap file to read input\n");
	printf("         -d <device id>   | read input from specific device\n");
	printf("         -r               | use RRDTool\n\n");
	printf("Example: capture -v -i ~/example.pcap\n");
	printf("     or: capture -v -d eth0 -r");
	printf("\n");
	printf("This tool reads packets from a pcap file or a network device\n");

	exit(0);
}

/*** Packet Capturing *************************************************************** ***/
/************************************************************************************ ***/

/* Handler for the pcap_loop function (pcap.h)
 *
 * @param u_char*
 * @param struct pcap_pkthdr
 * @parm u_char
 *
 */
void process_handler(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p)
{
	packet_t *pkt = NULL;	/* the packet_t retrived by the captured packet */
	int i = 0;				/*counter */

	pkt = get_packet(h, p);	/* get the packet_t */

	/*** print packet on the standard output (if requested) ***/
	if(print) print_packet(pkt);

	/*** buffer insertion ***/
	if(!pkt)
	{
		if(verbose) printf("process_handler: unsupported packet (SEQ=%d)\n", count);
	}
	else
	{
		i = pkt->key % BUFFER_NUM;
		if(cbuffer_put(pkt, buffers[i]) > 0)
		{
			if(verbose) printf("process_handler: packet insert in buffer[%d] (SEQ=%d, buffer_size=%d)\n",
					i , pkt->seq_num, buffers[i]->size);
		}
		else
		{
			if(verbose) printf("process_handler: buffer[%d] full (size = %d), packet discarded\n",
					i ,buffers[i]->size);
			discarded++;
			free(pkt);	/* packet discarded */
			usleep(100000);
		}
	}
}

/* Routine to create a packet_t from the captured packet
 *
 * @param pcap_pkthdr*	a pointer to the pre-packet information
 * @param u_char*		a pointer to the captured packet
 *
 * @return a pointer to the new packet_t allocated, or NULL if is unsupported
 */
packet_t* get_packet(const struct pcap_pkthdr *h, const u_char *p)
{
	int offset = 0;		/* offset of the header (it depends on the datalink) */
	int hlen = 0;		/* ip packet length (bytes) */
	u_int length = 0;	/* captured packet length (bytes) */

	struct ether_header* ehdr;	/* header ethernet */
	struct ip* ip;				/* header ip */

	int plen;			/* packet length */
	struct udphdr* up;	/* udp header structure */

	struct tcphdr* tcp;	/* tcp header structure */

	u_short eth_type = 0;		/* ethernet type (it depends on datalink) */

	packet_t * pkt = malloc(sizeof(packet_t));	/* memory allocation */

	/*** Start packet processing ***/
	if(verbose) printf("get_packet: process(p_len=%d, datalink=%d)\n", h->len, datalink);

	length = (u_int) h->len;	/* length of the packet */
	count++; 					/* increase the number of captured packets (global) */

	ehdr = malloc(sizeof(struct ether_header));

	/*** save meta-information ***/
	pkt->timestamp = (u_int) h->ts.tv_sec;
	pkt->size = length;
	pkt->seq_num = count;

	/*** parsing the ethernet type ***/
	if(datalink == DLT_EN10MB)
	{
		offset = 0;
	}
	else if(datalink == 113 /* Linux cooked */)
	{
		offset = 16;
	}

	hlen = offset;	/* Header offset */

	if(datalink == 113)
	{
		eth_type = 0x0800;
	}
	else
	{
		memcpy(ehdr, p + hlen, sizeof(struct ether_header));
		hlen += sizeof(struct ether_header);
		eth_type = ntohs(ehdr->ether_type);
	}

	/**** Ip packet processing ****/
	if(eth_type == 0x0800)
	{
		eth_count++;	/* ethernet datagrams counter */

		ip = malloc(sizeof(struct ip));
		memcpy(ip, p+hlen, sizeof(struct ip));
		if(ip->ip_v != 4)
		{
			free(pkt);
			return NULL;	/* Only ipv4 */
		}

		/* save the ip address in struct in_addr */
		pkt->ip_src = ip->ip_src;
		pkt->ip_dst = ip->ip_dst;

		hlen += ((u_int) ip->ip_hl * 4); /* header length */

		/*** UDP packet ***/
		if(ip->ip_p == IPPROTO_UDP)
		{
			if(verbose) printf("get_packet: udp(prot=%d)\n", (int)ip->ip_p);

			udp_count++;		/* UDP packet counter (global) */
			udp_size += length;	/* UDP bytes counter (global) */
			pkt->key = 0;		/* hash_key for udp packet is 0 */

			up = malloc(sizeof(struct udphdr));			/* allocation udp packet */
			memcpy(up, p+hlen, sizeof(struct udphdr));	/* copy header contents */

			/* test for too short packet */
			hlen += sizeof(struct udphdr);
			plen = h->caplen - hlen;
			if(plen <= 0)	/* too short */
			{
				free(up);
				return NULL; 
			}

			/*** insert udp packet information in the packet struct ***/
			pkt->prot = ip->ip_p;

#ifdef __APPLE__ || __FAVOR_BSD
			pkt->src_port = up->uh_sport;
			pkt->dst_port = up->uh_sport;
#else
			pkt->src_port = up->source;
			pkt->dst_port = up->dest;
#endif

			free(up);	/* deallocation */
			return pkt;
		}

		/*** TCP packet ***/
		if(ip->ip_p == IPPROTO_TCP)
		{
			if(verbose) printf("get_packet: tcp(prot=%d)\n", (int)ip->ip_p);

			tcp_count++;		/* TCP packet counter (global) */
			tcp_size += length;	/* TCP bytes counter (global) */

			tcp = malloc(sizeof(struct tcphdr));		/* memory allocation for tcp packet */
			memcpy(tcp, p+hlen, sizeof(struct tcphdr));	/* coping tcp header contents */ 

			/* test for too short packet */
			hlen += sizeof(struct tcphdr);
			plen = h->caplen - hlen;
			if(plen <= 0)
			{
				free(tcp);
				return NULL; 
			}

			pkt->prot = ip->ip_p;

#ifdef __APPLE__ || __FAVOR_BSD
			pkt->src_port = tcp->th_sport;
			pkt->dst_port = tcp->th_dport;
#else
			pkt->src_port = tcp->source;
			pkt->dst_port = tcp->dest;
#endif

			pkt->key = flow_hash_key(pkt);	/* hash key */
			/*u_int* flgs  = &tcp->th_flags;
			pkt->fin_flag = *(flgs+TH_FIN);		 flags
			 */
			/*if(pkt->fin_flag == 1)
			{
				print_packet(pkt);
			}*/

			free(tcp);
			return pkt;
		}

		/*** ICMP packet ***/ 
		if(ip->ip_p == IPPROTO_ICMP)
		{
			other_count++;
			if(verbose) printf("get_packet: icmp(prot=%d)\n", (int)ip->ip_p);

			free(pkt);
			return NULL;
		}
		else /*** Unsupported protocol ***/
		{
			other_count++;
			if(verbose) printf("get_packet: unknow(prot=%d)\n", (int)ip->ip_p);

			free(pkt);
			return NULL;
		}
	}
	else	/*** not-ethernet packet ***/
	{
		not_eth_count++;
		if(verbose) printf("get_packet: unknow(not-ethernet)\n");

		free(pkt);
		return NULL;
	}
}

/*** Threads routines *************************************************************** ***/
/************************************************************************************ ***/

/* Start the capture routine (pcap_loop)
 *
 * @param void*
 */
static void* capture_routine(void* arg)
{
	printf(">>>> capture thread started\n");
	pcap_loop(arg, -1, process_handler, NULL);

	end = 1;

	pthread_exit(NULL);
}

/* Start a new store-thread for storing flows
 *
 * param void*
 */
void* store_routine(void* arg)
{
	struct store_routine_args* args;
	struct cbuffer* b;

	args = (struct store_routine_args*) arg;
	b = args->buffer;

	printf(">>>> store thread started\n");
	while(!end)
	{
		packet_t* p = cbuffer_get_next(b);
		/*if(verbose) printf("store_routine: packet extracted\n");*/
		struct meta_flow* meta = NULL;
		HASH_NODE* n = NULL;
		flow_t* f = NULL;

		if(p != NULL)
		{
			/*if(verbose) printf("store_routine: packet is NOT_NULL\n");*/
			if(p->prot == IPPROTO_TCP && p->key < HASH_SIZE)
			{
				if(verbose) printf("store_routine: packet extracted (SEQ=%d, size=%d)\n", p->seq_num, p->size);
				meta = flow_get_meta(p);
				/*print_packet(p);*/ /* DEBUG */

				/* FLOW */
				n = hashtable_get_node_from_meta(db, meta);
				if(n != NULL)
					f = n->f;

				if(f == NULL)
				{
					/* create a new flow and insert it in the hashtable */
					f = flow_create(meta, p);
					if(hashtable_insert_node(db, f))
					{
						f->flow_id = ++flows;
						if(verbose) printf("store_routine: >>> new flow added [key: %d, flow_id: %d] <<<\n", f->hash_key, f->flow_id);
					}
					else
					{
						if(verbose) printf("store_routine: <<<< ERROR creating new flow [key: %d] >>>>", f->hash_key);
						flows_err++;
					}
				}
				/*else if(p->fin_flag == 1)
				{
					u_int f_id = f->flow_id;

					hashtable_kill_node(db, dead_queue, n);
					if(verbose) printf("store_routine: flow deleted because FIN_ACK detected (flow_id: %u)\n", f_id);
				}*/
				else
				{
					/* update the flow with packet's information */
					if( flow_update(f, p, meta) == 1 )
					{
						if(verbose) printf("store_routine: flow updated [key: %u] [packet_seq: %u]\n", f->hash_key, p->seq_num);
					}
					else
					{
						if(verbose) printf("store_routine: %s [key: %u]\n", errflow, f->hash_key);
					}
				}

				free(meta);
				free(p);
			}
		}
		else
		{
			/*if(verbose) printf("store_routine: packet is NULL\n");*/
			if(p != NULL)
				free(p);
			usleep(100000);
			/*pthread_join(&capth, NULL);*/
		}
	}
	return 0;
}

/* Start a new killer-thread for deleting the expired node in the dead_queue
 *
 * @param void*
 */
void* killer_routine(void* arg)
{
	int i;
	HASH_NODE* current_node;
	flow_t* current_flow;

	if(verbose) printf(">>>> killer thread start\n");

	while(!end)
	{
		flow_update_time(time(NULL));

		if(verbose) printf(">>>> killer thread wakeup\n");

		i = 0;
		for(i=0; i<HASH_SIZE; i++)
		{
			if(db->heads[i].line_nodes != NULL)
			{
				current_node = db->heads[i].line_nodes;
				while(current_node != NULL)
				{
					current_flow = current_node->f;

					if(verbose) printf("     killer_routine: look for flow %d\n", current_flow->flow_id);

					if(flow_is_expired(current_flow))
					{
						if(verbose) printf("     killer_routine: flow %d is expired\n", current_flow->flow_id);
						dead_queue = hashtable_kill_node(db, dead_queue, current_node);
						if(verbose) printf("     killer_routine: node killed [key: %d, flow_id: %d]\n", i, current_flow->flow_id);
						/*usleep(100000);*/
					}

					current_node = current_node->next;
				}
			}
		}
		if(verbose) printf("<<<< killer thread sleep\n");
		sleep(60);
	}
	return 0;
}

/* Start a new dead-thread for check the expire node in the HASHTABLE.
 * If a node (flow) is expire, this thread push it in the dead_queue.
 *
 * @param void*
 */
void* dead_routine(void* arg)
{
	struct dead_node* next = NULL;

	if(verbose) printf(">>>> dead thread start\n");
	sleep(30);

	while(!end)
	{
		if(verbose) printf(">>>> dead thread wakeup\n");

		next = hashtable_dead_pop(dead_queue, next, NULL);

		while(next)
		{
			next = hashtable_dead_pop(dead_queue, next, NULL);
		}
		dead_queue = NULL;
		if(verbose) printf("<<<< dead thread sleep\n");
		sleep(60);
	}

	return 0;
}

/*** Signal Handlers **************************************************************** ***/
/************************************************************************************ ***/

/* Handler per SIGALR
 *
 * @param int the SIGNAL code 
 */
void alarm_handler(int signum)
{
	/*if(verbose) printf("\n>>>> SIGALRM recived\n");*/

	if(secs == 10)
	{
		if(verbose) printf(">>>> Saving graphs...\n");
		rrdsave();
		secs = 0;
	}
	else
		secs++;

	rrdupdate(tcp_size, udp_size, tcp_count, udp_count);
	/*if(verbose) printf("\n>>>> RRD updated\n");*/

	alarm(STEP);
}

/* Handler for SIGINT
 *
 * @param int
 */
void term_handler(int signum)
{
	if(verbose) printf("\n>>>> SIGINT recived\n");

	end = 1;	/* set 'end' global var */

	return;
}

/*** Outputs Functions Definition *************************************************** ***/
/************************************************************************************ ***/

/* Print counters on the standard output */
void print_counters()
{
	char temp[100];
	char printer[500] = "";

	write(1, "\n", 1);
	sprintf(temp, "* Totale pacchetti:		%d\n", count);
	strcat(printer, temp);
	sprintf(temp,"* Pacchetti ethernet:		%d\n", eth_count);
	strcat(printer, temp);
	sprintf(temp, "* Pacchetti non ethernet:	%d\n", not_eth_count);
	strcat(printer, temp);
	sprintf(temp, "*\n");
	strcat(printer, temp);
	sprintf(temp, "* Pacchetti TCP:		%d\n", tcp_count);
	strcat(printer, temp);
	sprintf(temp, "* Pacchetti UDP:		%d\n", udp_count);
	strcat(printer, temp);
	sprintf(temp, "* Altri pacchetti:		%d\n", other_count);
	strcat(printer, temp);
	sprintf(temp, "* Pacchetti scartati:		%d\n", discarded);
	strcat(printer, temp);

	write(1, printer, sizeof(printer));
}

/* Print the packet 
 * 
 * @param packet_t* a pointer to the to-print packet
 */
void print_packet(packet_t* pkt)
{
	if(!pkt)	/* unsupported packet (when pkt==NULL) */
	{
		printf("* ************************************* *\n");
		printf("  Packet number:        %d\n", count);
		printf("  >>>>>>>  Unsupported packet   <<<<<<<\n");
		printf("* ************************************* *\n\n");
	}
	else		/* print packet */
	{
		printf("* ************************************* *\n");
		printf("  Packet  number:       %d\n", pkt->seq_num);
		printf("  Packet  key:          %u\n", pkt->key);
		printf("  Timestamp:            %u\n", pkt->timestamp);
		printf("  Protocol:             %u\n", pkt->prot);
		printf("  Size:                 %u\n", pkt->size);
		printf("> src ip:               %s\n", inet_ntoa(pkt->ip_src));
		printf("  src port:             %d\n", ntohs(pkt->src_port));
		printf("> dest ip:              %s\n", inet_ntoa(pkt->ip_dst));
		printf("  dest port:            %d\n", ntohs(pkt->dst_port));
		/*printf("  fin_flag:             %u\n", pkt->fin_flag);*/
		printf("* ************************************* *\n\n");
	}
}

/* Get the json for the counters
 *
 * @return a string rappresentation for the counters (in json format)
 */
char* capture_get_json_counters(char* json)
{
	char temp[100];

	sprintf(json, "{\n");
	sprintf(temp, "    \"datagrams\":\"%u\",\n", count);
	strcat(json, temp);
	sprintf(temp, "    \"eth_datagrams\":\"%u\",\n", eth_count);
	strcat(json, temp);
	sprintf(temp, "    \"non_eth_datagrams\":\"%u\",\n", not_eth_count);
	strcat(json, temp);
	sprintf(temp, "    \"tcp_packets\":\"%u\",\n", tcp_count);
	strcat(json, temp);
	sprintf(temp, "    \"udp_packets\":\"%u\",\n", udp_count);
	strcat(json, temp);
	sprintf(temp, "    \"other_packets\":\"%u\",\n", other_count);
	strcat(json, temp);
	sprintf(temp, "    \"tcp_size\":\"%u\",\n", tcp_size);
	strcat(json, temp);
	sprintf(temp, "    \"udp_size\":\"%u\"\n", udp_size);
	strcat(json, temp);
	sprintf(temp, "}");
	strcat(json, temp);

	return json;
}

/* Get the json for flows
 *
 * @return a string rappresentation for the active flows (in json format)
 */
char* get_json_flows()
{
	int i;
	HASH_NODE* current_node;

	u_int json_size = 70+300*db->size;					/* estimated json size */
	char* json = calloc(json_size, sizeof(char));
	char* auxbuf = calloc(json_size, sizeof(char));
	char temp[1000];
	short first_flow = 1;
	u_int flow_strlen;

	printf("capture_get_json_flow: \n");

	sprintf(json, "{\n");
	sprintf(temp, "    \"active_flows\":\"%u\",\n", (u_int) db->size);
	strcat(json, temp);
	sprintf(temp, "    \"flows\":[\n");
	strcat(json, temp);

	/*** start hashtable node iteration ***/
	for(i=0; i<HASH_SIZE; i++) 	/* for each HASHNODE */
	{
		pthread_rwlock_rdlock(&(db->heads[i].sem));

		/*printf("    [%d]->\t", i);*/
		if(db->heads[i].line_nodes != NULL)
		{
			current_node = db->heads[i].line_nodes;

			pthread_rwlock_unlock(&(db->heads[i].sem));

			while(current_node != NULL)	/* for each node in the line */
			{
				flow_t* current_flow;

				char* flow = calloc(1000, sizeof(char));

				current_flow = current_node->f;

				/*pthread_rwlock_rdlock(&(current_flow->sem));*/

				/*printf("(%d)->", current_flow->flow_id);*/

				if(first_flow == 1)
				{
					sprintf(flow, "    {\n");
					first_flow = 0;
				}
				else
				{
					sprintf(flow, ",{\n");
				}

				/* DUMP */
				sprintf(temp, "        \"flow_id\":\"%u\",\n", current_flow->flow_id);
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"ip1\":\"%s\",\n", inet_ntoa(current_flow->ip1));
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"port1\":\"%u\",\n", ntohs(current_flow->port1));
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"ip2\":\"%s\",\n", inet_ntoa(current_flow->ip2));
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"port2\":\"%u\",\n", ntohs(current_flow->port2));
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"start_time\":\"%u\"\n", (u_int) current_flow->start);
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"last_update\":\"%u\",\n", (u_int) current_flow->last_update);
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"packet_num\":\"%u\",\n", current_flow->tot_pkt);
				strncat(flow, temp, strlen(temp));

				sprintf(temp, "        \"bytes\":\"%u\"", current_flow->tot_byte);
				strncat(flow, temp, strlen(temp));

				flow_strlen = strlen(flow);
				if((strlen(json) + flow_strlen) >= json_size)
				{
					printf("json is too short (%d)\n", json_size);
					strncpy(auxbuf, json, json_size);
					json_size = json_size*2;

					free(json);
					json = calloc(json_size, sizeof(char));

					strncpy(json, auxbuf, json_size);
					free(auxbuf);
					auxbuf = calloc(json_size, sizeof(char));
				}

				strncat(json, flow, strlen(flow));
				sprintf(flow, "\n    }");
				strncat(json, flow, strlen(flow));

				current_node = current_node->next;
				/*if(current_node == NULL)
					printf(" NULL\n");*/

				/*pthread_rwlock_unlock(&(current_flow->sem));*/

				/*free(flow);*/
			}
		}
		else
		{
			/*printf("NULL\n");*/
			pthread_rwlock_unlock(&(db->heads[i].sem));
		}
	}
	sprintf(temp, "        ]\n}");
	strcat(json, temp);
	/*printf(json);*/

	printf("capture_json_flows: returning json\n");
	return json;
}

/************************************************************************************ ***/
