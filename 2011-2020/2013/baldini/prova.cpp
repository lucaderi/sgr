#include <iostream>
#include <pcap.h>
#include <string.h>

#define PROMISC 1
#define NO_TIME_OUT 0

using namespace std;

int main(int argc,char** argv){
	pcap_t  *eth_in,*eth_out,*wlan_in,*wlan_out;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	eth_in = pcap_open_live(argv[1], 65535, PROMISC, 1, errbuf);
	if( pcap_setdirection(eth_in,PCAP_D_IN) == -1){cout << "error setting read direction" <<endl;return 1;}
	eth_out = pcap_open_live(argv[1], 65535, PROMISC, NO_TIME_OUT, errbuf);
	wlan_in = pcap_open_live(argv[2], 65535, PROMISC, 1, errbuf);
	if( pcap_setdirection(wlan_in,PCAP_D_IN) == -1){cout << "error setting read direction" <<endl;return 1;}
	wlan_out = pcap_open_live(argv[2], 65535, PROMISC, NO_TIME_OUT, errbuf);
	while(true){
		if( pcap_next_ex(eth_in, &header, &pkt_data) == 1){
			u_char* buf = new u_char[header->caplen];
			memcpy(buf,pkt_data,header->caplen); //Crea una copia indipendente del pacchetto !!!
			if( pcap_sendpacket(wlan_out, buf, header->caplen) == 0);
			delete [] buf;
		}
		if( pcap_next_ex(wlan_in, &header, &pkt_data) == 1){
			u_char* buf = new u_char[header->caplen];
			memcpy(buf,pkt_data,header->caplen); //Crea una copia indipendente del pacchetto !!!
			if( pcap_sendpacket(eth_out, buf, header->caplen ) == 0 );
			delete [] buf;
		}
	}
}
