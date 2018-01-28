#include "intestazione.h"
#include "pkt_analyzer.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>



void process_eth(struct ether_header *ehdr){
   if(ehdr==NULL)
      return;
   printf("ETH |  ");
   printf("SMAC: %s ",ether_ntoa((struct ether_addr*)ehdr->ether_shost));
   printf("DMAC: %s\n",ether_ntoa((struct ether_addr*)ehdr->ether_dhost));
}



void process_ip(struct ip *ip){
   if(ip->ip_v != 4)
      return;
   printf("IP  |  Proto: %d ",ip->ip_p);
   printf("Version: %d ",ip->ip_v);
   printf("Src: %s ",inet_ntoa(ip->ip_src));
   printf("Dst: %s\n",inet_ntoa(ip->ip_dst));
}

void process_tcp(struct tcphdr *tcp){
   if(tcp ==NULL)
      return;
   u_char flag;
   printf("TCP |  ");
   printf("Sport: %d ",ntohs(tcp->source));
   printf("Dport: %d ",ntohs(tcp->dest));
}

void process_udp(struct udphdr *udp){
   if(udp==NULL)
      return;
   printf("UDP |  ");
   printf("Sport: %d",ntohs(udp->source));
   printf("Dport: %d\n",ntohs(udp->dest));
}

void loopPacket(u_char *file,const struct pcap_pkthdr *pkt,const u_char *p) {
   extern int linkLayer;
   int offset=0, hlen;
   struct ether_header ehdr;
   struct ip ip;
   char c;
   u_short eth_type;
   if(file!=NULL)
      pcap_dump(file,pkt,p);
   
   printf("FRM |  Data: %s",ctime(&(pkt->ts.tv_sec)));
   hlen=offset;
   /* determinazione inizio header */
   if(linkLayer==DLT_EN10MB){
      offset=0;
      memcpy(&ehdr,p+hlen,sizeof(struct ether_header));
      hlen += sizeof(struct ether_header);
      eth_type=ntohs(ehdr.ether_type);
      if(hlen >= pkt->caplen) return; /* pkt too short */
	 process_eth(&ehdr);
      }
   else if(linkLayer==113){
      offset=16;
      eth_type=0x0800;
   }
   if(eth_type==0x0800){
      memcpy(&ip,p+hlen,sizeof(struct ip));
      hlen += ((u_int)ip.ip_hl*4);
      if(hlen >= pkt->caplen) return; /*pkt too short */
	 process_ip(&ip);
	 /* analisi protocollo TCP */
	 if(ip.ip_p == IPPROTO_TCP){
	    struct tcphdr tcp_hdr;
	    memcpy(&tcp_hdr,p+hlen,sizeof(struct tcphdr)); 
	    process_tcp(&tcp_hdr);
	 }
	 else if(ip.ip_p == IPPROTO_UDP){
	    struct udphdr udp_hdr;
	    memcpy(&udp_hdr,p+hlen,sizeof(struct udphdr));
	    process_udp(&udp_hdr);
	 }
   }
   printf("\n");
}
