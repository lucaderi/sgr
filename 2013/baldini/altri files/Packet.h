#ifndef Pachet_h
#define Pachet_h

#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>

#define UDP_PROT 17
#define TCP_PROT 6
#define HTTP_PORT 80

class Packet{
public:
char* pkt_data;
unsigned int byteSize;
string url;
struct timeval time;


char* getPayloadHTTP(char* buf,const unsigned int BUFSIZE){
	return (char*)url.c_str();
}
inline unsigned int hash(int n){
	unsigned int tmp =
			getSourceIP() ^
			getDestinationIP() ^
			getSourcePort() ^
			getDestinationPort()^
			getTos()
			;
	return tmp % n;
}
inline bool hasFinFlag(){
	return ( ((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->fin == 1 );
}
Packet(unsigned int psize,int sorce_IP,int dest_IP,int destPort,string s,struct timeval *t){
	this->time = *t;
	this->url = s;
	int tx_len = 0;

	char* sendbuf = (char*) malloc(psize);
	pkt_data = sendbuf;
	byteSize = psize;
	
	if(sendbuf==NULL)return;
	memset(sendbuf, 0, psize);
	struct ether_header *eh = (struct ether_header *) sendbuf;

	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	/* IP Header */
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16; // Low delay
	iph->id = htons(54321);
	iph->ttl = 255; // hops
	iph->protocol = 6; // TCP
	iph->saddr = (sorce_IP);/* Source IP address */
	iph->daddr = (dest_IP);/* Destination IP address */
	

	struct tcphdr* tcph = (struct tcphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	/* UDP Header */
	tcph->source = 888;
	tcph->dest = destPort;
	tcph->check = 0; // skip
	((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->fin = 0;
}

~Packet(){if(pkt_data)free(pkt_data);}

//ritorna IP di destinazione
u_int32_t get_destination_IP()const{
	if(pkt_data == NULL)return 0;
	struct iphdr *iph = (struct iphdr *) (pkt_data + sizeof(struct ether_header));
	return iph->daddr;
}
u_int32_t get_source_IP()const{
	if(pkt_data == NULL)return 0;
	struct iphdr *iph = (struct iphdr *) (pkt_data + sizeof(struct ether_header));
	return iph->saddr;
}
		
//setta IP di destinazione
void set_destination_IP(unsigned int ip)const{
	if(pkt_data == NULL)return;
	struct iphdr *iph = (struct iphdr *) (pkt_data + sizeof(struct ether_header));
	iph->daddr = htons(ip);
}

unsigned int getBytes(){
 return (byteSize);
	
}

friend std::ostream& operator<<(std::ostream& out,const Packet& p){
	out << "IP sorgente: "<< p.get_source_IP() << " - IP destinazione: " << p.get_destination_IP();
	return out;
}
int get_source_port(){return 123;}
int get_destination_port(){return 80;}
int get_tos(){return 0;}
inline const u_int32_t getSourceIP(){
			return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->saddr);
	}
	const inline  u_int32_t getDestinationIP(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->daddr);
	}
	inline const bool isTCP(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->protocol == TCP_PROT);
	}
	inline const bool isHTTP(){
		return (getSourcePort() == HTTP_PORT || getDestinationPort() == HTTP_PORT);
	}
	inline const bool isUDP(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->protocol == UDP_PROT);
	}
	inline const u_int16_t getSourcePort(){
		return (((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->source);
	}
	inline const u_int16_t getDestinationPort(){
		return (((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->dest);
	}
	inline const u_int8_t getTos(){
		return ((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->tos;
	}
};

#endif
