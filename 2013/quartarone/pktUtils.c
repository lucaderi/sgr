#include "pktUtils.h"
#include <stdio.h>
#include "flow.h"
#include "sniffer.h"
#include "data.h"

#define DEBUG

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

void tcp_analyzer(u_char *tcp_datagram, pkt_rec_t *pkt_dec ){
  
  struct tcphdr *hdr_tcp = (struct tcphdr*)tcp_datagram;
  pkt_dec->s_port = ntohs(hdr_tcp->source);
  pkt_dec->d_port = ntohs(hdr_tcp->dest);
  #ifdef DEBUG
  printf("TCP src port#####: %d\n",ntohs((u_short)hdr_tcp->source));
  printf("TCP dst port: %d\n",ntohs((u_short)hdr_tcp->dest));
#endif  
}

void udp_analyzer(u_char *udp_datagram, pkt_rec_t *pkt_dec){
  struct udphdr *hdr_udp = (struct udphdr*)udp_datagram;
  pkt_dec->s_port = ntohs((u_short)hdr_udp->source);
  pkt_dec->d_port = ntohs((u_short)hdr_udp->dest);

#ifdef DEBUG
  printf("UDP src port: %d\n",ntohs((u_short)hdr_udp->source));
  printf("UDP dst port: %d\n",ntohs((u_short)hdr_udp->dest));
#endif
}


/*  called by dispatcher 
 */
void ip_analyzer(u_char *pkt,const struct pcap_pkthdr* header, unsigned int pkt_size, int dir){
  
  u_short ip_len;
  struct ip *pkt_ip = (struct ip *)pkt;
  int hdr_ip_len;
  pkt_rec_t *pkt_dec;

  pkt_dec = (pkt_rec_t *)malloc(sizeof(pkt_rec_t));
  pkt_dec->inOut = dir;

  //get verson
  
  //check availability
  hdr_ip_len = pkt_ip->ip_hl*4;
  //gestire errore pacchetto troppo lungo
  if(hdr_ip_len > header->caplen)
    return;
  ip_len = ntohs(pkt_ip->ip_len);
  data->ip_v4++;
  data->ip_v4_bytes = pkt_size;
#ifdef DEBUG
  printf("IP version: %d\n",pkt_ip->ip_v);
  printf("IP header lenght: %d\n",pkt_ip->ip_hl*4);
  printf("IP lenght: %d\n", ip_len);
  printf("IP src: %s\n",inet_ntoa(pkt_ip->ip_src));
  printf("IP dst: %s\n",inet_ntoa(pkt_ip->ip_dst));
#endif
  switch(pkt_ip->ip_p){
    case IPPROTO_TCP:{
      tcp_analyzer(pkt + hdr_ip_len, pkt_dec);
      data->tcp++;
      data->tcp_bytes = pkt_size;
    }break;
    case IPPROTO_UDP:{
      udp_analyzer(pkt + hdr_ip_len, pkt_dec);
      data->udp++;
      data->udp_bytes = pkt_size;
    }break;
    default: {
      data->other++;
      data->other_bytes = pkt_size;
    }
  }

  pkt_dec->src = pkt_ip->ip_src;
  pkt_dec->dst = pkt_ip->ip_dst;
  pkt_dec->proto = pkt_ip->ip_p;
  pkt_dec->size = pkt_size;
  pkt_dec->time = header->ts;
  u_int hash = fhash(pkt_dec);
  pkt_dec->hash = hash;
  int index = pkt_dec->time.tv_sec % FLOW_BUF_NO;
  put_buff(&flow_buffer[index],pkt_dec);
//  fprintf(stderr,"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ INDEX: %d\n",index);
}

