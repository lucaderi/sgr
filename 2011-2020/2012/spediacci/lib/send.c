#include "send.h"
#include "arp.h"

#define EI_HDR_LEN  (ETHER_HDR_LEN + IPV4_HDR_LEN)

u_int16_t ipv4_cs(const struct ip *ip) {
  union {
    u_int32_t s32;
    u_int16_t s16[2];
  } sum;
  u_int16_t *p = (u_int16_t *) ip, *end = (u_int16_t *) ((char *) ip + IPV4_HDR_LEN);
  sum.s32 = 0;
  for (; p < end; p++)
    sum.s32 += *p;
  return ~ (sum.s16[0] + sum.s16[1]);
}

ssize_t send_pkt(const char *msg,
		 size_t msg_len,
		 int flags,
		 const struct sockaddr_in *addr,
		 DnaSocket *skt) {
  struct ether_addr dest_mac;
  ssize_t sent = -1;
  if (skt->shutdown) {
    errno = EBADF;
  } else {
    if (arp_get(&dest_mac, addr->sin_addr, skt)) {
      errno = ECONNREFUSED;
    } else {
      char buffer[MTU];
      struct ether_header *eth = (struct ether_header *) buffer;
      struct ip *ip = (struct ip *) &buffer[ETHER_HDR_LEN];
      u_int16_t remain = msg_len;
      u_int16_t ipv4_off = 0;
      int first = 1;
      sent = 0;
      while (remain > 0) {
	int send_res;
	u_int16_t proto_hdr_len;
	u_int16_t tot_send;
	u_int16_t hdr, body, ipv4_body;
	int mf;
	 
	/* ETHERNET */
	MAC_CPY(&eth->ether_dhost, &dest_mac);                    /* destination mac address             */
	MAC_CPY(&eth->ether_shost, &skt->skt->mac);               /* source mac address                  */
	eth->ether_type  = htons(ETHERTYPE_IP);

	/* IPV4 */
	ip->ip_hl  = 5;                                           /* header len (measure unit: 4 octets) */
	ip->ip_v   = 4;                                           /* ip version                          */
	ip->ip_tos = 0;                                           /* type of service                     */
	ip->ip_id  = skt->id++;                                   /* "unique" id                         */
	ip->ip_p   = skt->proto.proto_id;                         /* upper level protocol                */
	ip->ip_src = skt->skt->addr;                              /* source ip address                   */
	ip->ip_dst = addr->sin_addr;                              /* destination ip address              */
	
	proto_hdr_len = first ? skt->proto.make_hdr(eth, ip, msg, msg_len, addr, skt) : 0;
	hdr = first ? EI_HDR_LEN + proto_hdr_len : EI_HDR_LEN;
	body = min(MTU - hdr, remain);
	ipv4_body = first ? body + proto_hdr_len : body;

	mf = remain != body;
	if (mf) {
	  /* ipv4 offset must be a multiple of 8 */
	  u_int16_t decrease = ipv4_body % 8;
	  ipv4_body -= decrease;
	  body -= decrease;
	}

	/* IPV4 AGAIN */
	ip->ip_len = IPV4_HDR_LEN + msg_len + proto_hdr_len;      /* header + payload                    */
	ip->ip_len = htons(ip->ip_len);                           /* ip len                              */
	ip->ip_off = mf ? ipv4_off | 0x2000 : ipv4_off;
	ip->ip_off = htons(ip->ip_off);                           /* offset                              */
	ip->ip_ttl = mf ? IPFRAGTTL : IPDEFTTL;                   /* time to live                        */
	ip->ip_sum = 0;
	ip->ip_sum = ipv4_cs(ip);                                 /* checksum                            */

	/* MSG COPY */
	memcpy(&buffer[hdr], &msg[sent], body);                   /* packet data                         */

	/* send packet */
	tot_send = hdr + body;
	pthread_spin_lock(&skt->skt->write_lock);
	while ((send_res=pfring_send(skt->skt->skt, buffer, tot_send, 1)) == -1
	       && !(flags & MSG_DONTWAIT) ) {
	}
	if (send_res != -1)
	  skt->skt->pkt_send++;
	pthread_spin_unlock(&skt->skt->write_lock);
	if (send_res == (int) tot_send) {
	  sent += body;
	  ipv4_off += ipv4_body / 8;
	  remain -= body;
	  first = 0;
	} else {
	  sent = -1;
	  errno = EINTR;
	  remain = 0; /* break from the while */
	}
      }
    }
  }
  return sent;
}

