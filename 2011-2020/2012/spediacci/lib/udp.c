#include "includes.h"

u_int16_t udp_cs(const struct ip *ip,
		 const struct udphdr *udp,
		 const char *msg,
		 size_t msg_len) {
  union {
    u_int16_t part[2];
    in_addr_t addr;
  } addr1;
  union {
    u_int16_t part[2];
    in_addr_t addr;
  } addr2;
  union {
    u_int16_t s16[2];
    u_int32_t s32;
  } sum;
  const u_int16_t *pmsg, *pmsg_end;
  addr1.addr = ip->ip_src.s_addr;
  addr2.addr = ip->ip_dst.s_addr;
  sum.s32 = htons(IPPROTO_UDP) +
    udp->source + udp->dest + udp->len + udp->len + udp->check +
    addr1.part[0] + addr1.part[1] +
    addr2.part[0] + addr2.part[1];
  /* payload */
  if (msg_len % 2) {
    pmsg_end = (u_int16_t *) (msg + msg_len - 1);
    sum.s32 += *((u_int8_t *) pmsg_end);
  } else
    pmsg_end = (u_int16_t *) (msg + msg_len);
  for (pmsg=(u_int16_t *) msg; pmsg < pmsg_end; pmsg++) {
    sum.s32 += *pmsg;
    if (sum.s32 & 0x80000000)
      sum.s32 = sum.s16[0] + sum.s16[1];
  }
  while (sum.s16[1])
    sum.s32 = sum.s16[0] + sum.s16[1];
  return ~ sum.s16[0];
}

u_int16_t udp_make_hdr(const struct ether_header *eth,
		       const struct ip *ip,
		       const char *msg,
		       size_t msg_len,
		       const struct sockaddr_in *addr,
		       const DnaSocket *skt) {
  struct udphdr *udp = (struct udphdr *) ((char *) ip + ip->ip_hl * 4);
  u_int16_t len = UDP_HDR_LEN + msg_len;
  udp->source  = skt->port;
  udp->dest    = addr->sin_port;
  udp->len     = htons(len);
  udp->check   = 0;
  udp->check   = udp_cs(ip, udp, msg, msg_len);
  if (!udp->check)
    udp->check = 0xffff;

  /* unused params */
  (void) eth;

  return UDP_HDR_LEN;
}
