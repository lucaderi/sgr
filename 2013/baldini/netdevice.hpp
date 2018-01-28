#ifndef netdevice_hpp
#define netdevice_hpp

#include <pcap.h>
#include <vector>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include "packet.hpp"

#define PROMISC 1
#define NO_TIME_OUT 0
#define SNAPLEN 65535

using namespace std;

class net_device{

private:
	pcap_t* handle;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
public:
	char errbuf[PCAP_ERRBUF_SIZE];
	static char err_s[PCAP_ERRBUF_SIZE];

	net_device(){
		errbuf[0] = '\0';
		handle = NULL;
		header = NULL;
		pkt_data = NULL;
	}
	~net_device(){if(handle)pcap_close(handle);}

	/* Get all available device names */
	static vector<char*>* alldevs(){
		vector<char*>* v = new vector<char*>();
		pcap_if_t *alldevs;
		if (pcap_findalldevs(&alldevs, err_s) == -1)return NULL;
		/* Print the list */

		for(pcap_if_t* d=alldevs; d ; d=d->next)
			v->push_back(d->name);
		return v;
	}

	/* Get the name of an available device */
	static char* getADevice(){
		return pcap_lookupdev(err_s);
	}

	/* Open the device of name : name in live time*/
	inline bool openLive(char* name){
		return ( handle = pcap_open_live(name, SNAPLEN, PROMISC, NO_TIME_OUT, errbuf) );
	}
	/* Open a Pcap File*/
	inline bool openOffLine(char* fileName){
		 return ( handle = pcap_open_offline(fileName,errbuf) );
	}

	/* Close the device */
	inline void close(){
		if(handle)pcap_close(handle);
		handle = NULL;
	}
	 /* Read the packet
	  *return:
      * 1 the packet was read without problems
      * 0 packets are being read from a live capture, and the timeout expired
      * -1   an error occurred while reading the packet
      * -2  packets are being read from a ``savefile'', and there are no more packets to read from the savefile.
	  * */
	inline int readPkt(){
		return pcap_next_ex(handle, &header, &pkt_data);
	}
	/**
	* Get pcap data just read
	*/
	inline const u_char* getPktData(){
		return pkt_data;
	}
	/**
	* Get pcap header just read
	*/
	inline struct pcap_pkthdr* getPcapHeader(){
		return header;
	}
	/**
	 * Write the packet
	 */
	inline bool write(packet* p){
		return ( pcap_sendpacket(handle, p->getPktData(), p->getPktDataLen() ) == 0 );
	}
	/**
	 * will only  capture  packets  received  by  the device
	 */
	inline bool setReadOnlyMode(){
		if( pcap_setdirection(handle,PCAP_D_IN) == -1){cout << "error setting read direction" <<endl;return false;}
		return true;
	}

};


#endif



