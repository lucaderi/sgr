#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include "flow.h"

#define TIMEOUT 1500
#define CAPSIZE 65535
#define ERR_BUF_SIZE 128
#define PROISC 1



int datalink;
int pkt_size;
int header_len;

pkt_rec_t record;

#endif
