#pragma once

#include "includes.h"

extern ssize_t send_pkt(const char *msg,
			size_t msg_len,
			int flags,
			const struct sockaddr_in *addr,
			DnaSocket *skt);

extern u_int16_t ipv4_cs(const struct ip *ip);
