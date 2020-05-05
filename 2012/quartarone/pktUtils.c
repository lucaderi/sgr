#include "pktUtils.h"
#include <stdio.h>
#include "flow.h"
#include "sniffer.h"


int get_header_len(int datalink_id){
  switch (datalink_id){
    case DLT_NULL:
    case DLT_PPP:
    case DLT_LOOP: return 4;
    case DLT_EN10MB: return sizeof(struct ether_header);
    case DLT_RAW: return 0;
    case DLT_IEEE802: return 22;
    case DLT_IEEE802_11: return 32;
    case DLT_LINUX_SLL: return 16;
    default: return -1;
  }
}

void tcp_analyzer(u_char *tcp_datagram){
  
  struct tcphdr *hdr_tcp = (struct tcphdr*)tcp_datagram;
#ifdef DEBUG
  printf("TCP src port: %d\n",ntohs((u_short)hdr_tcp->source));
  printf("TCP dst port: %d\n",ntohs((u_short)hdr_tcp->dest));
#endif  
}

void udp_analyzer(u_char *udp_datagram){
  struct udphdr *hdr_udp = (struct udphdr*)udp_datagram;
#ifdef DEBUG
  printf("UDP src port: %d\n",ntohs((u_short)hdr_udp->source));
  printf("UDP dst port: %d\n",ntohs((u_short)hdr_udp->dest));
#endif
}


void ip_analyzer(u_char *pkt,const struct pcap_pkthdr* header){
  
  u_short ip_len;
  struct ip *pkt_ip = (struct ip *)pkt;
  int hdr_ip_len;


  //get verson
  
  //check availability
  hdr_ip_len = pkt_ip->ip_hl*4;
  if(hdr_ip_len > header->caplen)
    return;
  ip_len = ntohs(pkt_ip->ip_len);
#ifdef DEBUG
  printf("IP version: %d\n",pkt_ip->ip_v);
  printf("IP header lenght: %d\n",pkt_ip->ip_hl*4);
  printf("IP lenght: %d\n", ip_len);
  printf("IP src: %s\n",inet_ntoa(pkt_ip->ip_src));
  printf("IP dst: %s\n",inet_ntoa(pkt_ip->ip_dst));
#endif
  switch(pkt_ip->ip_p){
    case IPPROTO_TCP:
      tcp_analyzer(pkt + hdr_ip_len);
      break;
    case IPPROTO_UDP:
      
      udp_analyzer(pkt + hdr_ip_len);
      break;
  }

  record.src = pkt_ip->ip_src;
  record.dst = pkt_ip->ip_dst;
  record.proto = pkt_ip->ip_p;
  record.size = pkt_size;
  record.time = header->ts;
 // u_int hash = fhash(&record);
  int index = header->ts.tv_usec % FLOW_BUF_NO;
  put_buff(&flow_buffer[index],&record);
  //fprintf(stderr,"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ INDEX: %d\n",index);




}


void tcp_process(u_char *ptr){
  
}
