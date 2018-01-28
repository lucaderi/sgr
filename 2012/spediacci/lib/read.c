#include <unistd.h>

#include "includes.h"
#include "read.h"
#include "arp.h"
#include "udp.h"
#include "send.h"

int write_pkt(u_char *buffer, size_t len, struct sockaddr_in *addr, DnaSocket *skt);

int parse_pkt(void *pkt, size_t pkt_len, int isdna, void *skt) {
  DnaSocket *dest;
  int32_t remain;
  struct ether_header *eth = (struct ether_header *) pkt;
  int ret = -1;
  PfSocket *pfskt;
  DnaSocket *dnaskt;
  if (isdna) {
    dnaskt = (DnaSocket *) skt;
    pfskt = dnaskt->skt;
  } else {
    dnaskt = NULL;
    pfskt = (PfSocket *) skt;
  }
  remain = pkt_len - ETHER_HDR_LEN;
  if (remain >= 0 &&
      (MAC_CMP(&eth->ether_dhost, &pfskt->mac)    == 0 ||
       MAC_CMP(&eth->ether_dhost, &mac_broadcast) == 0) ) {
    switch (ntohs(eth->ether_type)) {
    case ETHERTYPE_IP:
      goto ipv4;
    case ETHERTYPE_ARP:
      goto arp;
    }
  }
  return ret;

  /************* LEVEL 3 *************/
  struct ip *ip;
 ipv4:
  ip = (struct ip *) (pkt + ETHER_HDR_LEN);
  u_int ip_len = ip->ip_hl * 4;
  if (ip_len >= IPV4_HDR_LEN) {
    remain -= ip_len;
    if (remain >= 0     &&
	ip->ip_v == 4   &&
	ip->ip_ttl > 0  &&
	IPV4_CMP(&ip->ip_dst, &pfskt->addr) == 0) {
      switch (ip->ip_p) {
      case UDP_PROTO:
	goto udp;
      }
    }
  }
  return ret;

  struct arphdr *arp;
 arp:
  arp = (struct arphdr *) (pkt + ETHER_HDR_LEN);
  remain -= ARP_HDR_LEN;
  if (remain >= 0 &&
      ntohs(arp->ar_hrd) == ETHER_PROTO  &&
      ntohs(arp->ar_pro) == ETHERTYPE_IP &&
      arp->ar_hln        == ETH_ALEN     &&
      arp->ar_pln        == IPV4_LEN) {
    char *msg = (char *) arp;
    struct ether_addr *src_mac  = (struct ether_addr *) (&msg[ 8]);
    struct in_addr    *ip_src   = (struct in_addr    *) (&msg[14]);
    struct ether_addr *dest_mac = (struct ether_addr *) (&msg[18]);
    struct in_addr    *ip_dest  = (struct in_addr    *) (&msg[24]);
    if (MAC_CMP(dest_mac, &pfskt->mac) == 0) {
      switch (ntohs(arp->ar_op)) {
      case ARPOP_REQUEST:
	if (IPV4_CMP(ip_dest, &pfskt->addr) == 0)
	  send_arp_reply(*ip_src, *src_mac, pfskt);
	/* anyway act like a response and store it! */
      case ARPOP_REPLY:
	arp_put(*src_mac, *ip_src, 1, pfskt);
	break;
      }
    }
  }
  return ret;
  
  /************* LEVEL 4 *************/

  struct udphdr *udp;
 udp:
  udp = (struct udphdr *) (pkt + ETHER_HDR_LEN + ip_len);
  u_int16_t udp_len = ntohs(udp->len);
  size_t body = udp_len - UDP_HDR_LEN;
  u_char *msg = ((u_char *) udp) + UDP_HDR_LEN;
  dest = skts[udp->dest];
  if (dest &&
      udp_len >= UDP_HDR_LEN &&
      remain >= udp_len  &&
      !ipv4_cs(ip) &&
      !udp_cs(ip, udp, (char *) msg, body)) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = ip->ip_src;
    addr.sin_port = udp->source;
    switch (write_pkt(msg, body, &addr, dest)) {
    case 1:
      dest->pkt_zero++;
      sem_post(&dest->sem);
    case 0:
      dest->pkt_recv++;
      break;
    case -1:
      dest->pkt_drop++;
      pfskt->pkt_drop++;
    }
    ret = dest == dnaskt;
  }
  return ret;
}

void *reader_loop(void *arg) {
  PfSocket *pfskt = (PfSocket *) arg;
  u_char *pkt = NULL;
  struct pfring_pkthdr hdr;
  int ret;
  pfring_stat old_stat;
  u_int32_t c = 1;
  int slow = 1;
  old_stat.recv = old_stat.drop = 0;
  memset(&hdr, 0, sizeof(struct pfring_pkthdr));
  while ((ret=pfring_recv(pfskt->skt, &pkt, 0, &hdr, slow ? 0 : 0)) >= 0) {
    if (ret) {
      parse_pkt(pkt, hdr.len, 0, pfskt);
      pfskt->pkt_recv++;
    }
    if (!(--c)) {
      pfring_stat stats;
      if (!pfring_stats(pfskt->skt, &stats)) {
	u_int64_t recv_diff = (stats.recv - old_stat.recv);
	slow = recv_diff && (stats.drop - old_stat.drop) * 1000 / recv_diff > 5 ? 0 : 1;
	old_stat = stats;
      }
      c = slow ? 100000 : 1000000;
      search_closed_sockets();
    }
  }
  pthread_exit(NULL);
}

int read_init(PfSocket *skt) {
  return pthread_create(&skt->reader, NULL, &reader_loop, skt);
}
