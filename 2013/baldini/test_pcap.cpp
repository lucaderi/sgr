#include <pcap.h>
#include <vector>
#include <iostream>
#include "netdevice.hpp"
#include "packet.hpp"
int main(int argc,char** argv){
	/*
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
		pcap_if_t *alldevs;int res;
		if ((res= pcap_findalldevs(&alldevs, errbuf)) == -1)std::cout << "nada\n";
		else std::cout << "ok\n";
		for(pcap_if_t* d=alldevs; d ; d=d->next){
			std::cout << (d->name) 	<<std::endl;

		}
		/* Print the list */
		if(argc != 2){std::cout << "Errore numero argomenti"<<std::endl;return 1;}
		net_device dev;
		bool r = dev.openLive(argv[1]);
		if(r == false)std::cout << "Errore apertura dev: " << dev.errbuf <<std::endl;
		dev.datalink();
		while(true)
		{
			int ris = dev.readPkt();
			if(ris == 1){
				packet p(dev.getPktData(),dev.getPcapHeader());
			}
			else {std::cout << "errore lettura da rete" <<std::endl;return 1;}
		}


}





