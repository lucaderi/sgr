/*
 * capture.h
 *
 *  Created on: 01-ott-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 * 
 * @version 2.0
 */

#ifndef CAPTURE_H_
#define CAPTURE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <errno.h>

#define VERSION "2.0"

#define FLOW_THREAD_NUM 2
#define HASH_SIZE 100 		/* Hashtable size */
#define BUFFER_NUM 2

typedef struct packet		/* Packet structure */
{
	u_int key;				/* Hash key for this packet */
	u_int timestamp;		/* Arrival time for the packet */
	u_int seq_num;			/* Sequence number of this packet */
	u_char prot;			/* Protocol type */
	struct in_addr ip_src;	/* Source IP Address */
	struct in_addr ip_dst;	/* Destination IP Address */
	u_short src_port;		/* Source port */
	u_short dst_port;		/* Destination port */
	u_int size;				/* Packet size */
	u_int fin_flag:1;		/* Header flags */
} packet_t;

#define PACKET_SIZE sizeof(struct packet)

/*** ********************************************************************************************* ***/

int verbose;
int print;
int datalink;

/*** ********************************************************************************************* ***/

/* Routine to create a packet_t from the captured packet
 *
 * @return a new packet_t
 */
packet_t* get_packet(const struct pcap_pkthdr *h, const u_char *p);

/* Handler for the pcap_loop function (pcap.h) */
void process_handler(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p);

/* Get the json for the counters
 *
 * @return a string rappresentation for the counters (in json format)
 */
char* capture_get_json_counters(char* json);

/* Get the json for flows
 *
 * @return a string rappresentation for the active flows (in json format)
 */
char* get_json_flows();

/*** ********************************************************************************************* ***/

#endif /* CAPTURE_H_ */

