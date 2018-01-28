#include "pkt_info.h"
#include <time.h>
#include <stdio.h>

#define PRIME 65521

void getCaptureTime(t_pkt_info* info, char* time_buf, int buf_size)
{
	struct tm *ts = localtime(&info->capture_time);
	strftime(time_buf, buf_size, "%a %Y-%m-%d %H:%M:%S %Z", ts);
}

u_char getPktProtocol(t_pkt_info *info, char *protocol)
{
	return info->ip_p;
}

char *getSrcAddr(t_pkt_info *info)
{
	return inet_ntoa(info->src_addr);
}

uint16_t getSrcPort(t_pkt_info *info)
{
	return ntohs(info->src_port);
}

char *getDstAddr(t_pkt_info *info)
{
	return inet_ntoa(info->dst_addr);
}

uint16_t getDstPort(t_pkt_info *info)
{
	return ntohs(info->dst_port);
}

/* Returns the right-aligned n bits of x starting from the bit in p-th position, with the less significative bit at position 0 */
unsigned getbits(unsigned x, int p, int n)
{
	return (x >> (p+1-n)) & ~(~0 << n);
}

unsigned int toHash(t_pkt_info *info)
{
	unsigned int hash = 0;
	unsigned int scalar = 0;
	hash += ((info->src_addr.s_addr)>>24) * ((info->dst_addr.s_addr)>>24);
	hash += getbits(info->src_addr.s_addr,23,8) * getbits(info->dst_addr.s_addr,23,8);
	hash += getbits(info->src_addr.s_addr,15,8) * getbits(info->dst_addr.s_addr,15,8);
	hash += ((info->src_addr.s_addr)&~(~0<<8)) * ((info->dst_addr.s_addr)&~(~0<<8));
	hash = (hash % PRIME) << 16;
	scalar += ((info->src_port)>>8) * ((info->dst_port)>>8);
	scalar += ((info->src_port)&~(~0<<8)) * ((info->dst_port)&~(~0<<8));
	hash += scalar % PRIME;
	hash += info->ip_p;
	return hash;
}
