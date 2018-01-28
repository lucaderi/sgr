/*
 * AvvedutoSniffer.h
 *      Author: Giovanni Avveduto
 *      SGR Exercise
 */

#ifndef AVVEDUTOSNIFFER_H_
#define AVVEDUTOSNIFFER_H_
#include <netinet/in.h>
#include <sys/types.h>

/*flow element*/
struct flow_bidir {
	in_addr_t ip_src, ip_dst;
	u_short port_src, port_dst;
	u_long pkt_in, pkt_out;
	u_long byte_in, byte_out;
	uint32_t start_time;
	uint32_t last_time;
	u_char type,pad1,pad2,pad3;
};

/*queue element*/
struct queue_elem {
	in_addr_t ip_src, ip_dst;
	u_short port_src, port_dst;
	u_char type,pad1,pad2,pad3;
	uint32_t timestamp;
	uint32_t byte_len;
};

unsigned int hash(struct queue_elem *key);

#endif /* AVVEDUTOSNIFFER_H_ */
