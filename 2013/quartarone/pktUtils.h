#ifndef __PKTUTILS_H__
#define __PKTUTILS_H__

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>

#include "flow.h"
#include "data.h"


int get_header_len(int datalink_id);

void tcp_analyzer(u_char *tcp_datagram, pkt_rec_t *pkt_dec );

void udp_analyzer(u_char *udp_datagram, pkt_rec_t *pkt_dec);

void ip_analyzer(u_char *pkt,const struct pcap_pkthdr* header, unsigned int pkt_size, int dir);



#endif
