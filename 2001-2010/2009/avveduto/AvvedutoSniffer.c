/*
 * AvvedutoSniffer.c
 *      Author: Giovanni Avveduto
 *      SGR Exercise
 */

#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>

#include "AvvedutoSniffer.h"
#include "hashtbl.h"

int print_packet = 0;
int print_flow = 0;
int debug = 0;
int verbose = 0;

#define BYTETOCAPTURE 128 /*Bytes*/
struct pcap_pkthdr *header;
const u_char *pack;
pcap_t *descr;
int res = 0;

int end = 0;

int promisc = 0;
int deleterrd = 0;
int mac_retrieved = 0;

/*rrdupdate every x seconds*/
unsigned int rrdalarm;
unsigned int alarmtime = 1;
unsigned int alarmcount = 0;
/*rrd update every x seconds*/
unsigned int rrdupdatetime = 1;
/*step resolution of graph*/
unsigned int graphstep = 1;
/*refresh interval of graph in seconds*/
unsigned int rrdgraphtime = 5;
/*Maximum flow lifetime*/
unsigned int flow_lifetime = 30;
/*maximum time in seconds from last received flows packet*/
unsigned int flow_timeout = 5;
/*collect flows every x seconds*/
unsigned int flow_alarm_time = 1;

char macaddress[20];
/*RRD graph windows size, in minutes*/
char window[11] = "15m";

int datalink;
/*counters*/
u_long totalcount = 0;
u_long tcpcount = 0;
u_long udpcount = 0;
u_long icmpcount = 0;
u_long othertcount = 0;
u_long ipcount = 0;
u_long ip6count = 0;
u_long arpcount = 0;
u_long otherpcount = 0;
u_long sentbytes = 0;
u_long receivedbytes = 0;
u_long totalbytes = 0;

char *rrdname = "AvvedutoSniffer.rrd";
char *imagename = "AvvedutoSniffer.png";
/*Hash Table of flow records*/
HASHTBL *table = NULL;
/*List of expired flows*/
struct dead_hashnode **node_expired;

int nthread = 1;
int hash_table_size;

/*Max size of hash table*/
#define MAX_HASH_SIZE 10000
#define QUEUE_SIZE 1000
/*Queues array*/
static struct queue **queues;
/*Thread waiting structures*/
int *waiting;
pthread_mutex_t *w_mutex;
pthread_cond_t *w_cond;

/*element of hash table*/
struct hash_elem {
	struct hash_elem* next;
	uint32_t init_time;
	uint32_t last_time;
	in_addr_t ip_src, ip_dst;
	u_short port_src, port_dst;
	u_short type;
	u_long pkt_in, pkt_out;
	u_long byte_in, byte_out;
};

/*queue*/
struct queue {
	int empty;
	//unsigned int size;
	unsigned int push_idx;
	unsigned int pop_idx;
	struct queue_elem **array;
};

/*return hash of element key*/
unsigned int hash(struct queue_elem *key) {
	unsigned int hashval = 0;
	hashval += key->ip_src;
	hashval += key->ip_dst;
	hashval += key->port_src;
	hashval += key->port_dst;
	hashval += key->type;
	return hashval;
}

/*insert the element in the appropriate queue*/
void queue_put(struct queue_elem *elem) {
	/*queue id where enqueue element*/
	int q_id = hash(elem) % nthread;
	if (debug)
		printf("PUT: hash:%u queue:%u pos:%u\n", hash(elem), q_id, queues[q_id]->push_idx);
	if (debug)
		printf("PUT MEM: %p\n", elem);

	/*if not full enqueue element*/
	if ((queues[q_id]->push_idx - queues[q_id]->pop_idx) < QUEUE_SIZE)
	{
		queues[q_id]->array[queues[q_id]->push_idx % QUEUE_SIZE] = elem;
		queues[q_id]->push_idx ++;
	}
	/*if full queue discard element*/
	else {
		if (debug) printf("Queue full: %d\n",q_id);
		free(elem);
		return;
	}
	/*if analyzer waiting wake it up*/
	if (waiting[q_id]) {
		pthread_mutex_lock(&(w_mutex[q_id]));
		waiting[q_id]=0;
		pthread_cond_signal(&(w_cond[q_id]));
		pthread_mutex_unlock(&(w_mutex[q_id]));
	}
}

/*return element from th_id queue*/
struct queue_elem * queue_get(int th_id) {

	struct queue_elem *q;
	/*if not empty return element*/
	if ((queues[th_id]->pop_idx != queues[th_id]->push_idx)) {
		q = queues[th_id]->array[queues[th_id]->pop_idx % QUEUE_SIZE];

		if (debug) printf("GET:%u:%u:%u\n", hash(q), th_id, queues[th_id]->pop_idx);
		if (debug) printf("PUT MEM: %p\n", q);
		queues[th_id]->pop_idx ++;
		return q;
	}
	/*if empty queue return NULL*/
	else {
		if (debug) printf("Get EMPTY QUEUE");
		return NULL;
	}
}

/*Handle packet printing, and insert it in queues*/
void processPacket(struct pcap_pkthdr* pkthdr, const u_char* packet) {
	/*if packet is NULL return*/
	if((pkthdr==NULL)||(packet==NULL)) return;

	int offset = 0;
	u_short eth_type;
	struct ether_header *ehdr;
	totalbytes += pkthdr->len;

	/*Switch Case on Datalink type*/
	switch (datalink) {
	case DLT_EN10MB: {
		ehdr= (struct ether_header*) (packet+offset);
		offset += sizeof(struct ether_header);
		eth_type = ntohs(ehdr->ether_type);
		if (debug) printf("Process Packet\n");

		if (offset >= pkthdr->caplen)
			return; /* Pkt too short */

		/*Calculating troughput to local macaddress of broadcast macaddress*/
		if (strcmp(ether_ntoa((struct ether_addr *) ehdr->ether_shost),
				macaddress) == 0) {
			sentbytes += pkthdr->len;
		} else if ((strcmp(ether_ntoa((struct ether_addr *) ehdr->ether_dhost),
				macaddress) == 0) || (strcmp(ether_ntoa(
				(struct ether_addr *) ehdr->ether_dhost), ether_ntoa(
				ether_aton("ff:ff:ff:ff:ff:ff"))) == 0)) {
			receivedbytes += pkthdr->len;
		}

		/*print Timestamp*/
		char time[80];
		struct tm * localt = localtime(&pkthdr->ts.tv_sec);
		strftime(time, 80, "%a %d %b %Y %H:%M:%S", localt);
		if (print_packet)
			printf("Timestamp: %s.%d\n", time, pkthdr->ts.tv_usec);
		totalcount++;
	}
		break;

	default:
		if (print_packet)
			printf("Datalink non supportato\n");
		//free(ehdr);
		return;
	}

	switch (eth_type) {
	case ETHERTYPE_IP: /*0x0800 IP */
	{
		ipcount++;
		struct ip *ip;
		//ip = calloc(1, sizeof(struct ip));
		//memcpy(ip, packet + offset, sizeof(struct ip));
		ip=(struct ip*) (packet+offset);

		if (ip->ip_v != 4) {
			if (print_packet)
				printf("Wrong Packet\n\n");
			return; /* IPv4 only */
		}
		if (print_packet)
			printf("Protocol IP : ");

		offset += ((u_int) ip->ip_hl * 4);
		if (offset >= pkthdr->caplen) {
			if (print_packet)
				printf("Short Packet\n\n");
			return; /* Pkt too short */
		}

		/*if TCP print IP:PORT*/
		if (ip->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcph;
			//tcph = calloc(1, sizeof(struct tcphdr));
			//memcpy(tcph, packet + offset, sizeof(struct tcphdr));
			tcph=(struct tcphdr*) (packet+offset);

			if (print_packet)
				printf("TCP\n");
			offset += tcph->th_off;
			if (offset >= pkthdr->caplen) {
				if (print_packet)
					printf("Short Packet\n\n");
				return; /* Pkt too short */
			}
			if (print_packet)
				printf("From: %s : %d\n", inet_ntoa(ip->ip_src),
						ntohs(tcph->th_sport));
			if (print_packet)
				printf("To: %s : %d\n", inet_ntoa(ip->ip_dst),
						ntohs(tcph->th_dport));

			/*if print flows enqueue element*/
			if (print_flow) {
				struct queue_elem *elem = calloc(1, sizeof(struct queue_elem));

				elem->ip_src = ip->ip_src.s_addr;
				elem->ip_dst = ip->ip_dst.s_addr;
				elem->port_src = tcph->th_sport;
				elem->port_dst = tcph->th_dport;
				elem->type = ip->ip_p;

				elem->timestamp = pkthdr->ts.tv_sec;
				elem->byte_len = pkthdr->len;
				queue_put(elem);
			}

			tcpcount++;
			//free(tcph);
		}
		/*if UDP print IP:PORT*/
		else if (ip->ip_p == IPPROTO_UDP) {
			struct udphdr *udph;
			if (print_packet)
				printf("UDP\n");
			//udph = calloc(1, sizeof(struct udphdr));
			//memcpy(udph, packet + offset, sizeof(struct udphdr));
			udph=(struct udphdr*) (packet+offset);

			offset += sizeof(struct udphdr);
			if (offset >= pkthdr->caplen) {
				if (print_packet)
					printf("Short Packet\n\n");
				return;
			}
			if (print_packet)
				printf("From: %s : %d\n", inet_ntoa(ip->ip_src),
						ntohs(udph->uh_sport));
			if (print_packet)
				printf("To: %s : %d\n", inet_ntoa(ip->ip_dst),
						ntohs(udph->uh_dport));

			/*if print flow enqueue element*/
			if (print_flow) {
				struct queue_elem *elem = calloc(1, sizeof(struct queue_elem));

				elem->ip_src = ip->ip_src.s_addr;
				elem->ip_dst = ip->ip_dst.s_addr;
				elem->port_src = udph->uh_sport;
				elem->port_dst = udph->uh_dport;
				elem->type = ip->ip_p;

				elem->timestamp = pkthdr->ts.tv_sec;
				elem->byte_len = pkthdr->len;
				queue_put(elem);
			}
			udpcount++;
			//free(udph);

		}
		/*if ICMP print IP*/
		else if (IPPROTO_ICMP) {
			offset += sizeof(struct icmp);
			if (print_packet)
				printf("ICMP\n");
			if (print_packet)
				printf("From: %s\n", inet_ntoa(ip->ip_src));
			if (print_packet)
				printf("To: %s\n", inet_ntoa(ip->ip_dst));

			/*if print flow enqueue element*/
			if (print_flow) {
				struct queue_elem *elem = calloc(1, sizeof(struct queue_elem));

				elem->ip_src = ip->ip_src.s_addr;
				elem->ip_dst = ip->ip_dst.s_addr;
				elem->port_src = 0;
				elem->port_dst = 0;
				elem->type = ip->ip_p;

				elem->timestamp = pkthdr->ts.tv_sec;
				elem->byte_len = pkthdr->len;
				queue_put(elem);
			}

			icmpcount++;
		}
		/*if OTHER PROTOCOLS print nothing*/
		else {
			othertcount++;
			if (print_packet)
				printf("Protocol Unhandled\n");
		}

		//free(ip);
	}
		break;
		/*print ARP Packets*/
	case ETHERTYPE_ARP: {
		arpcount++;

		offset += sizeof(struct arphdr);
		if (offset >= pkthdr->caplen) {
			if (print_packet)
				printf("Short Packet ARP\n\n");
			return;
		}
		if (print_packet)
			printf("Protocol ARP\n");

	}
		break;
		/*print IPv& Packets*/
	case ETHERTYPE_IPV6: {
		ip6count++;
		struct ip6_hdr *ip6;
		//ip6 = calloc(1, sizeof(struct ip6_hdr));
		//memcpy(ip6, (packet + offset), sizeof(struct ip6_hdr));
		ip6=(struct ip6_hdr*) (packet+offset);

		offset += sizeof(struct ip6_hdr);
		if (offset >= pkthdr->caplen) {
			if (print_packet)
				printf("Short Packet IPv6\n\n");
			return; /*Packet Too Short*/
		}
		if ((ip6->ip6_ctlun.ip6_un2_vfc >> 4) != 6) {
			if (print_packet)
				printf("Wrong Packet\n");
			return; /*Only IPv6*/
		}
		if (print_packet)
			printf("Protocol IPv6 : ");

		if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
			struct tcphdr *tcph;
			//tcph = calloc(1, sizeof(struct tcphdr));
			//memcpy(tcph, packet + offset, sizeof(struct tcphdr));
			tcph=(struct tcphdr*) (packet+offset);

			offset += tcph->th_off;
			if (offset >= pkthdr->caplen) {
				if (print_packet)
					printf("Short Packet\n\n");
				return;
			}
			if (print_packet)
				printf("TCP\n");
			char buf[INET6_ADDRSTRLEN];
			if (print_packet)
				printf("From: %s : %d\n", inet_ntop(AF_INET6, &ip6->ip6_src,
						buf, sizeof(buf)), ntohs(tcph->th_sport));
			if (print_packet)
				printf("To: %s : %d\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf,
						sizeof(buf)), ntohs(tcph->th_dport));

			tcpcount++;
			//free(tcph);
		} else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
			struct udphdr *udph;
			//udph = calloc(1, sizeof(struct udphdr));
			//memcpy(udph, packet + offset, sizeof(struct udphdr));
			udph=(struct udphdr*) (packet+offset);

			offset += sizeof(struct udphdr);
			if (offset >= pkthdr->caplen) {
				if (print_packet)
					printf("Short Packet\n\n");
				return; /*Packet too short*/
			}
			if (print_packet)
				printf("UDP\n");
			char buf[INET6_ADDRSTRLEN];
			if (print_packet)
				printf("From: %s : %d\n", inet_ntop(AF_INET6, &ip6->ip6_src,
						buf, sizeof(buf)), ntohs(udph->uh_sport));
			if (print_packet)
				printf("To: %s : %d\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf,
						sizeof(buf)), ntohs(udph->uh_dport));

			udpcount++;
			//free(udph);
		} else if (IPPROTO_ICMPV6) {
			offset += sizeof(struct icmp6_hdr);
			if (print_packet)
				printf("ICMPv6\n");
			char buf[INET6_ADDRSTRLEN];
			if (print_packet)
				printf("From: %s\n", inet_ntop(AF_INET6, &ip6->ip6_src, buf,
						sizeof(buf)));
			if (print_packet)
				printf("To: %s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf,
						sizeof(buf)));
			icmpcount++;
		} else {
			othertcount++;
			if (print_packet)
				printf("Protocol Unhandled\n");
		}
		//free(ip6);
	}
		break;
	default: {
		otherpcount++;
		if (print_packet)
			printf("Protocol Unhandeld\n");
	}
	}
	if (print_packet)
		printf("\n");
	//free(ehdr);
}

/*Set EUID to "nobody"*/
int noMoreRoot() {
	struct passwd *pw = NULL;
	/*if not root*/
	if (geteuid() != 0)
		return 0;
	else {
		char *user;
		pw = getpwnam(user = "nobody");
		if (pw != NULL) {
			if ((setegid(pw->pw_gid) != 0) || (seteuid(pw->pw_uid) != 0)) {
				//printf("Unable to change user to %s [%d: %d]\n", user, pw->pw_uid, pw->pw_gid);
				return 1;
			} else {
				//printf("User Nobody not found\n");
				return 1;
			}
		} else {
			//printf("User Changet to nobody");
			return 0;
		}
	}
}

/*if UID=root set EUID=root*/
int becameRoot() {
	//uid=geteuid();
	if (geteuid() == 0) {
		/*Root yet*/
		//printf("Root yet\n");
		return 0;
	} else {
		/*If have permission to set EUID to root*/
		if (getuid() == 0) {
			/*Set Effective UID to root*/
			//printf("Not Root yet\n");
			seteuid(0);
			return 0;
		} else
			return 1;
	}
}

/*format RRD CREATE command*/
void rrdcreate(char * create) {
	graphstep = graphstep * alarmtime;
	char temp[20] = "";
	strcat(create, "rrdtool create ");
	strcat(create, rrdname);
	strcat(create, " --step=");
	sprintf(temp, "%d ", graphstep);
	strcat(create, temp);
	strcat(create, "DS:nTCP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nPKT:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nUDP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nICMP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nOTHT:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nIP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nIP6:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nARP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:nOTHP:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:TOTALB:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:SENTB:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	strcat(create, " DS:RECVB:COUNTER:");
	sprintf(temp, "%d", graphstep * 2);
	strcat(create, temp);
	strcat(
			create,
			":0:1000000000 RRA:AVERAGE:0.5:1:3600 RRA:AVERAGE:0.5:60:1440 RRA:AVERAGE:0.5:3600:168");

	if (verbose)
		printf("%s\n\n", create);
	system(create);
}

/*format RRD UPDATE command*/
void rrdupdate(char * update) {
	//char update[200]="";
	strcat(update, "rrdtool update ");
	strcat(update, rrdname);
	strcat(
			update,
			" --template=nPKT:nTCP:nUDP:nICMP:nOTHT:nIP:nIP6:nARP:nOTHP:TOTALB:SENTB:RECVB N:");
	char scount[126] = "";
	sprintf(scount, "%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld",
			totalcount, tcpcount, udpcount, icmpcount, othertcount, ipcount,
			ip6count, arpcount, otherpcount, totalbytes, sentbytes,
			receivedbytes);
	strcat(update, scount);
	if (verbose)
		printf("%s\n\n", update);
	system(update);
}

/*format RRD GRAPH command*/
void rrdgraph(char * graph) {
	//char graph[400]="";
	strcat(graph, "rrdtool graph ");
	strcat(graph, imagename);
	strcat(
			graph,
			" --vertical-label '     Protocolli di Rete | Protocolli di Trasporto' --start=end-");
	strcat(graph, window);
	strcat(graph, " --width 800 --height 400 --step ");
	char step[10] = "";
	sprintf(step, "%d", graphstep);
	strcat(graph, step);
	strcat(graph, " DEF:avtcp=");
	strcat(graph, rrdname);
	strcat(graph, ":nTCP:AVERAGE");
	strcat(graph, " DEF:avudp=");
	strcat(graph, rrdname);
	strcat(graph, ":nUDP:AVERAGE");
	strcat(graph, " DEF:avicmp=");
	strcat(graph, rrdname);
	strcat(graph, ":nICMP:AVERAGE");
	strcat(graph, " DEF:otht=");
	strcat(graph, rrdname);
	strcat(graph, ":nOTHT:AVERAGE");
	strcat(graph, " DEF:avip=");
	strcat(graph, rrdname);
	strcat(graph, ":nIP:AVERAGE");
	strcat(graph, " DEF:avip6=");
	strcat(graph, rrdname);
	strcat(graph, ":nIP6:AVERAGE");
	strcat(graph, " DEF:avarp=");
	strcat(graph, rrdname);
	strcat(graph, ":nARP:AVERAGE");
	strcat(graph, " DEF:othp=");
	strcat(graph, rrdname);
	strcat(graph, ":nOTHP:AVERAGE");

	strcat(graph, " DEF:totalb=");
	strcat(graph, rrdname);
	strcat(graph, ":TOTALB:AVERAGE");
	strcat(graph, " CDEF:totalkb=totalb,1024,/");

	strcat(graph, " DEF:sentb=");
	strcat(graph, rrdname);
	strcat(graph, ":SENTB:AVERAGE");
	strcat(graph, " CDEF:sentkb=totalb,1024,/");

	strcat(graph, " DEF:recvb=");
	strcat(graph, rrdname);
	strcat(graph, ":RECVB:AVERAGE");
	strcat(graph, " CDEF:recvkb=totalb,1024,/");

	strcat(graph, " DEF:totalpkt=");
	strcat(graph, rrdname);
	strcat(graph, ":nPKT:AVERAGE");
	strcat(graph, " CDEF:tcpper=avtcp,totalpkt,/,100,*");
	strcat(graph, " CDEF:udpper=avudp,totalpkt,/,100,*");
	strcat(graph, " CDEF:icmpper=avicmp,totalpkt,/,100,*");
	strcat(graph, " CDEF:othtper=otht,totalpkt,/,100,*");
	strcat(graph, " CDEF:ipper=avip,totalpkt,/,100,*");
	strcat(graph, " CDEF:ip6per=avip6,totalpkt,/,100,*");
	strcat(graph, " CDEF:arpper=avarp,totalpkt,/,100,*");
	strcat(graph, " CDEF:othpper=othp,totalpkt,/,100,*");
	strcat(graph, " VDEF:vtcp=tcpper,LAST");
	strcat(graph, " VDEF:vudp=udpper,LAST");
	strcat(graph, " VDEF:vicmp=icmpper,LAST");
	strcat(graph, " VDEF:votht=othtper,LAST");
	strcat(graph, " VDEF:vip=ipper,LAST");
	strcat(graph, " VDEF:vip6=ip6per,LAST");
	strcat(graph, " VDEF:varp=arpper,LAST");
	strcat(graph, " VDEF:vothp=othpper,LAST");

	strcat(graph, " VDEF:vatcp=tcpper,AVERAGE");
	strcat(graph, " VDEF:vaudp=udpper,AVERAGE");
	strcat(graph, " VDEF:vaicmp=icmpper,AVERAGE");
	strcat(graph, " VDEF:vaotht=othtper,AVERAGE");
	strcat(graph, " VDEF:vaip=ipper,AVERAGE");
	strcat(graph, " VDEF:vaip6=ip6per,AVERAGE");
	strcat(graph, " VDEF:vaarp=arpper,AVERAGE");
	strcat(graph, " VDEF:vaothp=othpper,AVERAGE");

	strcat(graph, " CDEF:rip=avip,-1,*");
	strcat(graph, " CDEF:rip6=avip6,-1,*");
	strcat(graph, " CDEF:rarp=avarp,-1,*");

	strcat(graph, " COMMENT:' ***TRANSPORT LAYER\\: Current % (Total %)***\\c'");
	strcat(graph, " COMMENT:' \\s'");

	strcat(graph, " AREA:avtcp#ff0000:'TCP\\:'");
	strcat(graph, " GPRINT:vtcp:'%.2lf%%'");
	strcat(graph, " GPRINT:vatcp:'(%.2lf%%)'");
	strcat(graph, " AREA:avudp#0000ff:'UDP\\::STACK'");
	strcat(graph, " GPRINT:vudp:'%.2lf%%'");
	strcat(graph, " GPRINT:vaudp:'(%.2lf%%)'");
	strcat(graph, " AREA:avicmp#00ff00:'ICMP\\::STACK'");
	strcat(graph, " GPRINT:vicmp:'%.2lf%%'");
	strcat(graph, " GPRINT:vaicmp:'(%.2lf%%)'");
	strcat(graph, " AREA:otht#00aa00:'Other\\::STACK'");
	//strcat(graph, ":STACK");
	strcat(graph, " GPRINT:votht:'%.2lf%%'");
	strcat(graph, " GPRINT:vaotht:'(%.2lf%%)'");

	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' ***NETWORK LAYER\\: Current % (Total %)***\\c'");
	strcat(graph, " COMMENT:' \\s'");

	strcat(graph, " AREA:rip#00ffff:'IP\\:'");
	strcat(graph, " GPRINT:vip:'%.2lf%%'");
	strcat(graph, " GPRINT:vaip:'(%.2lf%%)'");
	strcat(graph, " AREA:rip6#ffff00:'IPv6\\::STACK'");
	strcat(graph, " GPRINT:vip6:'%.2lf%%'");
	strcat(graph, " GPRINT:vaip6:'(%.2lf%%)'");
	strcat(graph, " AREA:rarp#ff00ff:'ARP\\::STACK'");
	strcat(graph, " GPRINT:varp:'%.2lf%%'");
	strcat(graph, " GPRINT:vaarp:'(%.2lf%%)'");
	strcat(graph, " AREA:othp#00aa00:'Other\\::STACK'");
	//strcat(graph, ":STACK");
	strcat(graph, " GPRINT:vothp:'%.2lf%%'");
	strcat(graph, " GPRINT:vaothp:'(%.2lf%%)'");

	strcat(graph, " VDEF:totallast=totalb,LAST");
	strcat(graph, " VDEF:totalavg=totalb,AVERAGE");
	strcat(graph, " VDEF:totalmin=totalb,MINIMUM");
	strcat(graph, " VDEF:totalmax=totalb,MAXIMUM");
	//char total[20];
	//sprintf(total," GPRINT:totalspeed:%.2lf%sBps");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " TEXTALIGN:left");
	strcat(graph, " COMMENT:'				*CURRENT*'");
	//strcat(graph," COMMENT:''");
	strcat(graph, " COMMENT:'		 *AVERAGE*'");
	strcat(graph, " COMMENT:'	  *MIN*'");
	strcat(graph, " COMMENT:'	   *MAX*'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " TEXTALIGN:left");
	strcat(graph, " LINE1:totalkb#000000:'Throughput\\:'");
	//strcat(graph," COMMENT:'Total Speed'");
	strcat(graph, " GPRINT:totallast:'	 %.2lf%sBps'");
	strcat(graph, " GPRINT:totalavg:'		%.2lf%sBps'");
	strcat(graph, " GPRINT:totalmin:'	%.2lf%sBps'");
	strcat(graph, " GPRINT:totalmax:'	%.2lf%sBps'");
	//strcat(graph,total);
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " COMMENT:' \\s'");
	strcat(graph, " VDEF:recvlast=recvb,LAST");

	strcat(graph, " GPRINT:recvlast:'Local Throughput (IN/OUT)\\: %.2lf%sBps'");
	strcat(graph, " VDEF:sentlast=sentb,LAST");

	strcat(graph, " GPRINT:sentlast:'/ %.2lf%sBps'");

	if (verbose)
		printf("%s\n\n", graph);
	system(graph);
	return;

}

/*print passed flow*/
void flow_print(struct flow_bidir *flow) {
	char sflow[300] = "";
	if (!flow) {
		return;
	}
	char temp[100] = "";
	switch (flow->type) {
	case IPPROTO_TCP:
		sprintf(temp, "TCP");
		break;
	case IPPROTO_UDP:
		sprintf(temp, "UDP");
		break;
	case IPPROTO_ICMP:
		sprintf(temp, "ICMP");
		break;
	default:
		sprintf(temp, "UNHANDLED (%hu)", flow->type);
		break;
	}
	sprintf(sflow, "Flow %s\nFrom: ", temp);
	sprintf(temp, "%s : %hu", inet_ntoa((struct in_addr) {flow->ip_src}),ntohs(flow->port_src));
	strcat(sflow,temp);
	strcat(sflow," To: ");
	sprintf(temp,"%s : %u\n",inet_ntoa((struct in_addr) {flow->ip_dst}),ntohs(flow->port_dst));
	strcat(sflow,temp);
	struct tm * localt = localtime((time_t*) &(flow->start_time));
	strftime(temp, 100, "%a %d %b %Y %H:%M:%S", localt);
	strcat(sflow,"Start: ");
	strcat(sflow,temp);
	localt = localtime((time_t*) &(flow->last_time));
	strftime(temp, 100, "%a %d %b %Y %H:%M:%S", localt);
	strcat(sflow,"\nEnd: ");
	strcat(sflow,temp);
	sprintf(temp,"\nPkt sent: %lu (%lu Byte) Pkt received: %lu (%lu Byte)\n",flow->pkt_in,flow->byte_in,flow->pkt_out,flow->byte_out);
	strcat(sflow,temp);
	printf("%s\n",sflow);
}

/*collect and print expired flows*/
int print_expired_flows() {

	struct dead_hashnode *current;
	/*free printed yet expired flows*/
	while ((current = *node_expired)) {		
		free(current->node->data);
		free(current);
		*node_expired = current->next;
	}

	/*retrieve expired flows to print, and print them*/
	hashtbl_remove(table, flow_lifetime, flow_timeout, node_expired);
	current = *node_expired;

	while (current) {
		flow_print(current->node->data);
		current = current->next;
	}
	return 0;
}

/*Handler of SIGALARM, used for RRD update and graph*/
void onalarm(int sig) {
	if (sig == SIGINT) {
		end = 1;
		return;
	}
	alarmcount++;

	/*RRD update*/
	if (!(alarmcount % rrdupdatetime)) {
		char update[300] = "";
		rrdupdate(update);
	}
	/*RRD graph*/
	if (!(alarmcount % rrdgraphtime)) {
		char graph[3000] = "";
		rrdgraph(graph);
	}

	rrdalarm = alarm(alarmtime);
}

/*print USAGE help*/
void help() {
	printf("\nusage:  AvvedutoSniffer [opts [optargs] ]\n");
	printf("		This sniffer needs root privileges\n");
	printf("		Options:\n");
	printf("		-d deviceName: specify the device name to sniff\n");
	printf("		-a: set device in promiscuous mode\n");
	printf("		-r rrdname: RRD filename\n");
	printf("		-i imagename: RRDgraph image filename\n");
	printf("		-c: delete RRD file if exists yet\n");
	printf("		-n: threads number\n");
	printf("		-v: verbose, print RRD commands\n");
	printf("		-p: print captured packet to stdout\n");
	printf("		-f: print flow info to stdout\n");
	printf("		-u updatetime: RRDupdates every x seconds (default 1)\n");
	printf("		-t rrdgraphtime: RRDgraph every x seconds (default 5)\n");
	printf("		-w windowsize: RRDgraph window's size in minutes (default 15)\n");
	printf("\n");
}

/*Pcap_loop thread*/
void * pcaploop(void *args) {
	while ((res = pcap_next_ex(descr, &header, &pack)) >= 0) {
		processPacket(header, pack);
	}
	end = 1;
	return NULL;
}

/*thread that print expired flows*/
void * flow_printer(void *args) {
	while (!end) {
		print_expired_flows();
		sleep(flow_alarm_time);
	}
	return NULL;
}

void * flow_analyzer(void *args) {
	int th_id = *((int*) args);
	struct queue_elem *qe;
	while (!end) {

		int size;
		if (!(queues[th_id]->empty))
			size = 1;
		else
			size = queues[th_id]->push_idx - queues[th_id]->pop_idx;

		while (size == 0) {

			pthread_mutex_lock(&(w_mutex[th_id]));
			waiting[th_id] = 1;
			pthread_cond_wait(&(w_cond[th_id]), &(w_mutex[th_id]));
			waiting[th_id] = 0;
			pthread_mutex_unlock(&(w_mutex[th_id]));

			if (!(queues[th_id]->empty))
				size = 1;
			else
				size = queues[th_id]->push_idx - queues[th_id]->pop_idx;
		}

		qe = queue_get(th_id);
		if (qe != NULL) {
			hashtbl_insert(table, qe);
			free(qe);
		}
	}
	return NULL;
}

/*Main program*/
int main(int argc, char *argv[]) {

	char errbuf[256];
	const char *device;

	if (getuid() != 0) {
		printf("Need root privileges\n");
		return (1);
	} else if (geteuid() != 0)
		becameRoot();
	int deviceset = 0;
	/*Managing Options*/
	if (argc > 1) {
		int arg = getopt(argc, argv, "d:ar:i:cvt:u:w:fpn:q");
		if (arg == -1) {
			help();
			return 3;
		}
		while (arg != -1) {
			switch (arg) {
			/*device name*/
			case 'd':
				device = optarg;
				deviceset = 1;
				break;
				/*promiscuos mode*/
			case 'a':
				promisc = 1;
				break;
				/*rrdname*/
			case 'r':
				rrdname = optarg;
				break;
				/*imagename*/
			case 'i':
				imagename = optarg;
				break;
				/*overwrite rrd files*/
			case 'c':
				deleterrd = 1;
				break;
				/*verbose mode*/
			case 'v':
				verbose = 1;
				break;
				/*rrdupdate every x seconds*/
			case 'u':
				rrdupdatetime = atoi(optarg);
				break;
				/*rrdgraph every x seconds*/
			case 't':
				rrdgraphtime = atoi(optarg);
				break;
				/*rrd graph window size*/
			case 'w':
			{
				int w =atoi(optarg);
				if (w<=5) w=6;
				sprintf(window, "%dm", w);
			}
				break;
			case 'f':
				print_flow = 1;
				break;
			case 'p':
				print_packet = 1;
				break;
				/*thread number*/
			case 'n':
				nthread = atoi(optarg);
				/*dedicate one core for picking up packets*/
				if (nthread > 1)
					nthread--;
				break;
				/*debug*/
			case 'q':
				debug = 1;
				break;
				/*print help usage if there are wrong options*/
			default:
				help();
				return 3;
				break;
			}
			arg = getopt(argc, argv, "d:ar:i:cvt:u:w:fpn:q");
		}
	}

	if (deviceset == 0)
		device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("Error opening device\n");
		return (2);
	}
	descr = pcap_open_live(device, BYTETOCAPTURE, promisc, 512, errbuf);
	if (descr == NULL) {
		printf("Cannot open device: %s\n", device);
		return (3);
	} else
		printf("Sniffing from device : %s\n", device);

	/*No More Root Privileges*/
	noMoreRoot();
	datalink = pcap_datalink(descr);

	/*Controlling if RRD exists, if not exists create it*/
	FILE *rrd = fopen(rrdname, "r");
	if ((rrd != NULL) && (deleterrd == 0)) {
		printf("%s found, continue using it.\n", rrdname);
	} else if ((rrd != NULL) && (deleterrd)) {
		char create[1000] = "";
		rrdcreate(create);
		printf("%s recreated\n", rrdname);
	} else /*if (rrd==NULL)*/
	{
		char create[1000] = "";
		rrdcreate(create);
		printf("%s created\n", rrdname);
	}

	/*Obtaining MAC ADDRESS*/
	system("rm macaddrfile");
	char cmd[50];
	//printf("ifconfig %s ether|grep ether |cut -b 8-24>>macaddrfile",device);
	sprintf(cmd, "ifconfig %s ether|grep ether |cut -b 8-24>>macaddrfile",
			device);
	printf(cmd);
	system(cmd);
	FILE *addrfile = fopen("macaddrfile", "r");
	fgets(macaddress, 18, addrfile);
	system("rm macaddrfile");
	struct ether_addr *ea = ether_aton(macaddress);
	if (ea) {
		sprintf(macaddress, "%s", ether_ntoa(ea));
		mac_retrieved = 1;
		if (verbose)
			printf("\nMAC:%s", macaddress);
	}
	printf("\n\n");

	if (print_flow) {
		/*Structure for control flow*/
		hash_table_size = ((int) (MAX_HASH_SIZE / nthread)) * nthread;
		if (hash_table_size <= 0)
			return 4;

		if (!(table = hashtbl_create(hash_table_size))) {
			printf("Errore durente la creazione dell'Hash Table\n");
			return 4;
		}
		/*dead_hashnode list*/
		node_expired = calloc(1, sizeof(struct dead_hashnode*));
		*node_expired=NULL;

		/*array of queues*/
		queues = calloc(nthread, sizeof(struct queue*));
		if (queues == NULL) {
			printf("Allocazione memoria non riuscita");
			return 4;
		}
		int j;
		/*initializing queues*/
		for (j = 0; j < nthread; j++) {
			struct queue_elem **array;
			array = calloc(1, QUEUE_SIZE * sizeof(struct queue_elem*));
			struct queue *q = calloc(1, sizeof(struct queue));
			q->array = array;
			q->pop_idx = 0;
			q->push_idx = 0;
			q->empty = 1;
			queues[j] = q;
		}

		/*Initialize mutex and conditional variables*/
		/*used to pause flow_analyzers in case of empty queues*/
		w_mutex = calloc(1, nthread * sizeof(pthread_mutex_t));
		w_cond = calloc(1, nthread * sizeof(pthread_cond_t));
		waiting = calloc(1, nthread * sizeof(int));
		for (j = 0; j < nthread; j++) {
			pthread_mutex_init(&(w_mutex[j]), NULL);
			pthread_cond_init(&(w_cond[j]), NULL);
		}

	}
	/*Creating and starting pcap_loop thread*/
	pthread_t loop;
	if (pthread_create(&loop, NULL, &pcaploop, NULL)) {
		printf("Thread non creato\n");
		return 5;
	}
	if (pthread_detach(loop)) {
		printf("Thread non partito\n");
		return 6;
	}

	if (print_flow){
		/*Create and start flow analyzer threads*/
		int j=0;
		int th_ids[nthread];
		pthread_t flow_an[nthread];
		for (j = 0; j < nthread; j++) {
			th_ids[j] = j;
			if (pthread_create(&flow_an[j], NULL, &flow_analyzer,
					(void*) &th_ids[j])) {
				printf("Thread non creato\n");
				return 5;
			}
			if (pthread_detach(flow_an[j])) {
				printf("Thread non partito\n");
				return 6;
			}
		}

		/*create and start flow printer thread*/
		pthread_t flow_printer_t;
		if (pthread_create(&flow_printer_t, NULL, &flow_printer, NULL)) {
			printf("Thread non creato\n");
			return 5;
		}
		if (pthread_detach(flow_printer_t)) {
			printf("Thread non partito\n");
			return 6;
		}
	}

	/*Setting ALARM SIGNAL used for rrd*/
	sigset_t signals;
	int signum;
	sigemptyset(&signals);
	sigaddset(&signals, SIGALRM);
	sigaddset(&signals, SIGINT);
	rrdalarm = alarm(alarmtime);

	while (!end) {
		sigwait(&signals, &signum);
		onalarm(signum);
	}

	hashtbl_destroy(table);
	printf("Terminated\n\n");
	return 0;
}

