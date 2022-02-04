#pragma once

#include "includes.h"

extern int read_init(PfSocket *skt);
extern ssize_t acquire_pkt(u_char *buffer, size_t buffer_len, struct sockaddr_in *addr, DnaSocket *skt);

