/*
 * analyzer.h
 *
 *  Created on: 02-giu-2009
 *      Author: Gianluca Medici 275788
 */

#ifndef ANALYZER_H_
#define ANALYZER_H_
#define SLL_ADDRLEN     		8				/* length of address field */
#include <GeoIP.h>
#include <GeoIPCity.h>


/* ************ PPP ************* */
typedef struct pppTunnelHeader {
  u_int16_t	unused, protocol;
} PPPTunnelHeader;

/* *********LINUX COOKED********* */
typedef struct sll_header {
         u_int16_t       sll_pkttype;    		/* packet type */
         u_int16_t       sll_hatype;     		/* link-layer address type */
         u_int16_t       sll_halen;      		/* link-layer address length */
         u_int8_t        sll_addr[SLL_ADDRLEN];	/* link-layer address */
         u_int16_t       sll_protocol;   		/* protocol */
} SLL_Header;

//void countRecordInfo(GeoIPRecord* record );
//void updateCollector(const struct ip *ip_header, int option);
void processPacket(u_char *args, const struct pcap_pkthdr *header,u_char *packet);

#endif /* ANALYZER_H_ */
