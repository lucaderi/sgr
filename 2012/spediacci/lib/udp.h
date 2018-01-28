#pragma once

#include "includes.h"

u_int16_t udp_make_hdr(const struct ether_header *eth,
		       const struct ip *ip,
		       const char *msg,
		       size_t msg_len,
		       const struct sockaddr_in *addr,
		       const DnaSocket *skt);

u_int16_t udp_cs(const struct ip *ip,
		 const struct udphdr *udp,
		 const char *msg,
		 size_t msg_len);
