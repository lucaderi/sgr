/*
 * GeoVis.h
 *
 *  Created on: 26-mag-2009
 *      Author: Gianluca Medici 275788
 */
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#ifndef GEOVIS_H_
#define GEOVIS_H_
#define BROWSER_PORT 			3001
#define FLAG_DUMMY_SOCKET		-999
//#define GOOGLE_MAP_KEY		"ABCDEFG"	/* Unused in the end */
#define VERSION				"0.1"
#define UNKNOWN_CITY		"Unknown"
#define UNKNOWN_LATLONG			0.00

extern struct nationHash* IpHastTable;				//Global pointer to the head of the hashTable

extern unsigned int PKTprocessed; 					//Global counter for packets that passed the pcap filter
extern unsigned int PKToutsideBuckett ;				//Global counter for unimplemented protocol packets
extern unsigned int PKTfromUnknowCity ;				//Global counter for unresolved city name
extern unsigned int PKTfromUnidentifiedCountry;		//Global counter for unresolved country code
extern unsigned int totalIpConsidered;				//Global counter for the number of ip address analyzed

#endif  /*GEOVIS_H_*/
