/*
 * analyzer.c
 *
 *  Created on: 02-giu-2009
 *      Author: Gianluca Medici 275788
 */
#include "GeoVis.h"
#include "myhash.h"
#include "analyzer.h"

#define PPPTYPE_IP					0x0021

unsigned int PKTprocessed = 0; 					//Global counter for packets that passed the pcap filter
unsigned int PKToutsideBuckett = 0;				//Global counter for unimplemented protocol packets
unsigned int PKTfromUnknowCity = 0;				//Global counter for unresolved city name
unsigned int PKTfromUnidentifiedCountry = 0;	//Global counter for unresolved country code
unsigned int totalIpConsidered = 0;				//Global counter for the number of ip address analyzed

extern GeoIP * giCitta;							//Global pointer at the GeoLite City opened database

struct nationHash * IpHastTable= NULL;			//Global pointer to the head of the hashTable

int datalink;									//represent the link layer type for the savefile

static void countRecordInfo(GeoIPRecord* record ){
	struct nationHash* nationBuckett;
	struct cityHash* cityBuckett;
	const char *code=record->country_code;
	char* cityName=NULL;
	float latitu=0;
	float longit=0;

	nationBuckett=find_Nation(&IpHastTable, code);

	if(record->city!= NULL) {
		cityName=record->city;
		latitu=record->latitude;
		longit=record->longitude;
	} else{
		cityName=UNKNOWN_CITY;
		latitu=UNKNOWN_LATLONG;
		longit=UNKNOWN_LATLONG;
		PKTfromUnknowCity++;
	}

	if (nationBuckett == NULL) {//the code was not added before

		addnumPKTandCity( &IpHastTable, code, record->country_name, cityName, latitu, longit);
	}
	else {//the nation code is already present

		(nationBuckett->numberPkt)++;//increment the number of packet for this nation


		cityBuckett = find_city(nationBuckett->listaCitta, cityName);

		if (cityBuckett != NULL) {//the city was already listed, increment the packets for city

			(cityBuckett->numberPkt)++;

		} else {//the city was not listed before, add the city to the list

			addCity(nationBuckett->listaCitta, cityName, latitu,
					longit);

		}
	}
}



static void updateCollector(const struct ip *ip_header, int option) {
	GeoIPRecord * record;

	/*Let me explain this part:
	 * if option is 1 collect both ip_dst and ip_src
	 * if option is 0 collect just the ip_dst
	 * if option is -1 collect just the ip_src
	 */

	if (option >= 0) {//collect the dst ip
		totalIpConsidered++;
		record = GeoIP_record_by_addr(giCitta, inet_ntoa(ip_header->ip_dst));

		if(record == NULL || record->country_code == NULL || strcmp(record->country_code, "--") == 0 || strcmp(record->country_code, "EU" ) == 0 || strcmp(record->country_code, "AP") == 0){//the nation code founded is not representable on a map
			PKTfromUnidentifiedCountry++;

		}else{
			countRecordInfo(record);

		}

	}
	if (option == 1 || option == -1) {//collect the src ip
		totalIpConsidered++;
		record = GeoIP_record_by_addr(giCitta, inet_ntoa(ip_header->ip_src));

		if(record == NULL || record->country_code == NULL || strcmp(record->country_code, "--") == 0 || strcmp(record->country_code, "EU" ) == 0 || strcmp(record->country_code, "AP") == 0){//the nation code founded is not representable on a map
			PKTfromUnidentifiedCountry++;

		}else{

			countRecordInfo(record);

		}

	}

}

void processPacket(u_char *args, const struct pcap_pkthdr *header,
		u_char *packet) {
	int option=0;

	const struct ether_header *ethernet;
	const struct ip * captIp;
	const struct pppTunnelHeader *ppp;
	const struct sll_header *linuxCooked;

	PKTprocessed++;
	option =(int)  *args;


	if ((datalink == DLT_EN10MB)) {/*Frame Ethernet*/
		ethernet = (struct ether_header*) (packet);

		if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
			captIp = (struct ip*) &packet[sizeof(struct ether_header)];

			updateCollector(captIp, option); /* Search for the country code
			 * of ip passed and update the collector
			 */
			return;
		}

	}

	if (datalink == DLT_PPP) {/*Frame PPP IP type 0x0021*/
		ppp = (struct pppTunnelHeader *) (packet);

		if (ntohs((int) ppp->protocol) == PPPTYPE_IP) {
			captIp = (struct ip*) &packet[sizeof(struct pppTunnelHeader)];

			updateCollector(captIp, option);
			return;
		}

	}
	if(datalink == DLT_LINUX_SLL){/*Frame LINUX_COOKED*/
		linuxCooked=(struct sll_header *)(packet);
		if(ntohs((int) linuxCooked->sll_protocol) == ETHERTYPE_IP){
			captIp= (struct ip*)	&packet[sizeof(struct sll_header)];

			updateCollector(captIp, option);
			return;
		}
	}

	PKToutsideBuckett++;
	return;

}
