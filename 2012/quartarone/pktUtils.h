#ifndef __PKTUTILS_H__
#define __PKTUTILS_H__



#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


int get_header_len(int datalink_id);

#endif
