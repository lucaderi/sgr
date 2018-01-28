/*
 * Flow.hpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (desensi@cli.di.unipi.it)
 *
 * Contains functions for creations and exportations of the flows.
 */

#ifndef FLOW_HPP_
#define FLOW_HPP_
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctime>
#include <queue>
#include <allocator.hpp>

#define MAX_FLOW_NUM 30

#define TCP_PROT_NUM 0x06
#define UDP_PROT_NUM 0x11

#include <allocator.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

/**
 * Element of the hash table.
 */
struct hashElement {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t dPkts;      /* Packets sent */
  u_int32_t dOctets;    /* Octets sent */
  timeval First;        /* Time at start of flow */
  timeval Last;         /* and of last packet of the flow (when a packet is captured */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int32_t hashId;		/* Id in the hash table */
};


/**
 * NetFlow v5 header.
 */
struct flow_ver5_hdr {
  u_int16_t version;                 /* Current version=5*/
  u_int16_t count;                   /* The number of records in PDU. */
  u_int32_t sysUptime;               /* Current time in msecs since router booted */
  u_int32_t unix_secs;               /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;              /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;           /* Sequence number of total flows seen */
  u_int8_t engine_type;              /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t engine_id;                /* Slot number of the flow switching engine */
  u_int8_t sampling_interval;
};


/**
 * Netflow v5 flow.
 */
struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent */
  u_int32_t dOctets;    /* Octets sent */
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow (when a packet is captured */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

/**
 * Netflow v5 record.
 */
struct netflow5_record {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[MAX_FLOW_NUM];
};


/**
 * Exports the flows.
 */
class Exporter{
private:
	int sock; ///<Socket file descriptor
	struct sockaddr_in addr; ///<Address of the collector
	ff::ff_allocator* ffalloc; ///<Fastflow's memory allocator
	uint32_t systemStartTime; ///< System start time
public:

	/**
	 * Constructor of the exporter.
	 * \param collectorAddress The ipv4 address of the collector.
	 * \param port The port on which is listening the collector.
	 * \param alloc The fastflow's allocator.
	 * \param systemStartTime The system start time.
	 */
	inline Exporter(char* collectorAddress, ushort port,ff::ff_allocator *alloc, uint32_t systemStartTime):ffalloc(alloc),
	systemStartTime(systemStartTime){
		/* Create socket */
		if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("Socket creation error");
			exit(-1);
		}
		/* Initialize address */
		memset((void *) &addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		/* Build address using inet_pton */
		if ( (inet_pton(AF_INET,collectorAddress, &addr.sin_addr)) <= 0) {
			perror("Address creation error");
			exit(-1);
		}
	}

	/**
	 * Prints the flow in a file.
	 * \param out The file where to print the flow.
	 * \param f The flow to print.
	 */
	inline void printFlow(FILE* out,hashElement* f){
		struct in_addr struaddr;
		/**inet_ntoa need the address in network byte order.**/
		struaddr.s_addr=f->srcaddr;
		char* addr=inet_ntoa(struaddr);
		fprintf(out,"%s|", addr);
		struaddr.s_addr=f->dstaddr;
		addr=inet_ntoa(struaddr);
		fprintf(out,"%s|", addr);
		fprintf(out,"%d|",f->dPkts);
		fprintf(out,"%d|",f->dOctets);
		fprintf(out,"%d|",f->First.tv_sec);
		fprintf(out,"%d|",f->Last.tv_sec);
		fprintf(out,"%d|",ntohs(f->srcport));
		fprintf(out,"%d|",ntohs(f->dstport));
		fprintf(out,"%d|",f->tcp_flags);
		fprintf(out,"%d|",f->prot);
		fprintf(out,"%d|",f->tos);
		fprintf(out,"\n");
	}

	/**
	 * Sends the expired flows to the collector.
	 * \param q A queue of expired flows.
	 * \param flowSequence The sequence number of the next record.
	 * \param out A pointer to the file where to print the flows.
	 */
	uint sendToCollector(std::queue<hashElement*>* q, u_int32_t flowSequence,FILE* out){
		uint size=q->size();
		if(size>MAX_FLOW_NUM)
			return -1;
		netflow5_record record;
		flow_ver5_hdr hdr;
		memset((void *) &record, 0, sizeof(record));
		hdr.version=htons(5);
		hdr.count=htons(q->size());
		timeval now;
		gettimeofday(&now,NULL);
		u_int32_t uptime=now.tv_sec*1000+now.tv_usec/1000-systemStartTime;
		hdr.sysUptime=htonl(uptime);
		hdr.unix_secs=htonl(now.tv_sec);
		hdr.unix_nsecs=htonl(now.tv_usec/1000);
		hdr.flow_sequence=htonl(flowSequence);
		hdr.engine_type=hdr.engine_id=hdr.sampling_interval=0;
		record.flowHeader=hdr;
		hashElement *f;
		flow_ver5_rec fr;
		fr.src_as=fr.dst_as=fr.dst_mask=fr.src_mask=fr.input=fr.output=fr.nexthop=fr.pad1=fr.pad2=0; //TODO Add routing informations
		uint i;
		for(i=0; !q->empty(); i++){
			f=q->front();
			q->pop();
			if(out!=NULL)
				printFlow(out,f);
			fr.srcaddr=f->srcaddr;
			fr.dstaddr=f->dstaddr;
			fr.srcport=f->srcport;
			fr.dstport=f->dstport;
			fr.tos=f->tos;
			fr.tcp_flags=f->tcp_flags;
			fr.prot=f->prot;
			fr.First=htonl(f->First.tv_sec*1000+f->First.tv_usec/1000-systemStartTime);
			fr.Last=htonl(f->Last.tv_sec*1000+f->Last.tv_usec/1000-systemStartTime);
			fr.dOctets=htonl(f->dOctets);
			fr.dPkts=htonl(f->dPkts);
			record.flowRecord[i]=fr;
			ffalloc->free(f);
		}

		if (sendto(sock,&record,sizeof(record)-((MAX_FLOW_NUM-size)*sizeof(flow_ver5_rec)), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("Request error");
			return -1;
		}
		return 0;
	}
};


/**
 * Checks if a flow is expired.
 * \param f The flow to check.
 * \param idle Max number of seconds of inactivity.
 * \param lifeTime Max number of life's seconds of a flow.
 * \param now A pointer to the current time (if it is NULL this function returns true).
 */
inline bool isExpired(hashElement* f, u_int32_t idle, u_int32_t lifeTime, time_t* now){
	if(now==NULL) return true;
	/**If the flow idle timeout is expired.**/
	if((*now-f->Last.tv_sec)>idle)
		return true;
	/**If the flow lifetime timeout is expired.**/
	if((f->Last.tv_sec-f->First.tv_sec)>lifeTime)
		return true;
	/**If FIN or RST are arrived.**/
	if((f->tcp_flags&0x5)!=0x0)
		return true;
	return false;
}

/**
 * Fill an hashElement with the information contained in a captured packet.
 * \param pkt The captured packet.
 * \param datalinkOffset The size of a datalink header.
 */
inline hashElement* getFlow(const unsigned char* pkt, int datalinkOffset, ff::ff_allocator *alloc){
	hashElement* f=(hashElement*)alloc->malloc(sizeof(hashElement));
	iphdr* ip=(struct iphdr*) (pkt+datalinkOffset);
	if(ip->version!=4) return NULL;
	f->prot=ip->protocol;
	f->tos=ip->tos;
	f->srcaddr=ip->saddr;
	f->dstaddr=ip->daddr;
	uint32_t ipHdrLen=(ip->ihl&0x0f)*4;
	int transportOffset=datalinkOffset+ipHdrLen;
	uint8_t newflags=0;
	if(ip->protocol==TCP_PROT_NUM){
		tcphdr* tcp=(struct tcphdr*)(pkt+transportOffset);
		f->srcport=tcp->source;
		f->dstport=tcp->dest;
		newflags|=((tcp->res2&0x2)<<6);
		newflags|=((tcp->res2&0x1)<<7);
		newflags|=((tcp->urg&0x1)<<5);
		newflags|=((tcp->ack&0x1)<<4);
		newflags|=((tcp->psh&0x1)<<3);
		newflags|=((tcp->rst&0x1)<<2);
		newflags|=((tcp->syn&0x1)<<1);
		newflags|=(tcp->fin&0x1);
	}else if(ip->protocol==UDP_PROT_NUM){
		udphdr* udp=(struct udphdr*)(pkt+transportOffset);
		f->srcport=udp->source;
		f->dstport=udp->dest;
	}else{
		f->srcport=f->dstport=0;
	}
	f->tcp_flags=newflags;
	return f;
}

/**
 * Returns true if the flows have the same key (<Tos,Level 4 protocol, Level 4 Source Port, Level 4 Destination Port,
 * Level 3 Source Address, Level 3 Destination Address>)
 * \param f1 The first flow.
 * \param f2 The second flow.
 */
inline bool equals(hashElement *f1, hashElement *f2){
	return f1->tos==f2->tos && f1->prot==f2->prot && f1->srcaddr==f2->srcaddr && f1->dstaddr==f2->dstaddr &&
			f1->srcport==f2->srcport && f1->dstport==f2->dstport;
}

#endif /* FLOW_HPP_ */
