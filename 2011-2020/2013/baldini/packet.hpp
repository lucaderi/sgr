/*
 * packet.hpp
 *
 *  Created on: 22/dic/2012
 *      Author: francesco
 */

#ifndef packet_hpp
#define packet_hpp

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

#define UDP_PROT 17
#define TCP_PROT 6
#define HTTP_PORT 80


class packet{
private:
	const u_char* pkt_data; //puntatori ai dati
	struct pcap_pkthdr header; //header pcap info dati letti
	int outDevId; //ID per l'interfaccia di uscita del pacchetto
public:
	packet(u_char* buf,struct pcap_pkthdr* h,int outDeviceId){
		pkt_data = buf;
		header = *h;
		outDevId = outDeviceId;
	}
	~packet(){
		if(pkt_data)delete [] pkt_data;
	}
	inline u_char* getPktData(){
		return (u_char*)pkt_data;
	}
	inline int getPktDataLen(){
		return header.caplen;
	}
	inline int getOutDevID(){
		return outDevId;
	}
	inline const bool isIPv4(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->version == 4);
	}
	inline const u_int32_t getSourceIP(){
			return ntohl(((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->saddr);
	}
	const inline  u_int32_t getDestinationIP(){
		return ntohl(((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->daddr);
	}
	inline const bool isTCP(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->protocol == TCP_PROT);
	}
	inline const bool isHTTP(){
		if(header.len < sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct tcphdr))return false;
		return (isIPv4() && isTCP() && (getSourcePort() == HTTP_PORT || getDestinationPort() == HTTP_PORT));
	}
	inline const bool isUDP(){
		return (((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->protocol == UDP_PROT);
	}
	inline const u_int16_t getSourcePort(){
		return ntohs(((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->source);
	}
	inline const u_int16_t getDestinationPort(){
		return ntohs(((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->dest);
	}
	inline const u_int8_t getTos(){
		return ((struct iphdr *) (pkt_data + sizeof(struct ether_header)))->tos;
	}
	inline bool hasTcpFinFlag(){
		return (((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->fin );
	}
	inline bool hasTcpAckFlag(){
		return (((struct tcphdr *) (pkt_data + sizeof(struct iphdr) + sizeof(struct ether_header)))->ack );
	}
	friend std::ostream& operator<<(std::ostream& out,packet& p){
		struct in_addr src;
		struct in_addr dst;
		src.s_addr =  (((struct iphdr *) (p.pkt_data + sizeof(struct ether_header)))->saddr);
		dst.s_addr = (((struct iphdr *) (p.pkt_data + sizeof(struct ether_header)))->daddr);
		char buf[20];
		strcpy(buf,inet_ntoa(src));
		out << "Source Ip: "<< buf  << " - Destination Ip: " << inet_ntoa(dst) << " ports = "<<p.getSourcePort()<<":"<<p.getDestinationPort();
		return out;
	}
	/**
	 * Tempo di Arrivo del pacchetto
	 */
	inline struct timeval* getTime(){
		return &(header.ts);
	}
	/**
	 * codice hash del pacchetto % n passato per argomento
	 */
	inline unsigned int hash(int n){
		unsigned int tmp = getSourceIP() ^ getDestinationIP();
		return tmp % n;
	}
	/**
	 * Restituisce il puntatore ai dati HTTP
	 */
	inline u_char* getHttpDataPointer(){
		const struct iphdr* h_ip = (const struct iphdr *) (pkt_data+sizeof(struct ether_header));
		const struct tcphdr   *h_tcp = (struct tcphdr *) (pkt_data + sizeof(struct ether_header) + sizeof(struct iphdr));
		return (u_char*)(pkt_data + sizeof(struct ether_header) +(h_ip->ihl * 4)+(h_tcp->doff * 4));
	}
	/**
	 * Numero di byte del payload http
	 */
	inline unsigned int getHttpPayloadLenght(){
		return (header.caplen - (getHttpDataPointer()-pkt_data));
	}
	/**
	 * Restituisce il puntatore buf passato come argomento,
	 * se nel payload HTTP è presente una richiesta GET, NULL
	 * altrimenti
	 * @param bufffer dove scrivere i dati
	 * @param BUFSIZE lunghezza del buffer
	 */

#define HOST "Host: "
#define HOST_L 6

inline char* getHttpHost(char* buf,const unsigned int size){
		u_char* data = getHttpDataPointer();
		int len = getHttpPayloadLenght();
		u_char tmp = data[4];
		data[4]='\0';
		if(strstr((char*)data,"GET") == NULL){return NULL;}
		data[4]=tmp;
		tmp = data[len-1];
		data[len-1]='\0';
		char* p;
		if( (p = strstr((char*)data,HOST)) == NULL){return NULL;}
		p = p + HOST_L;
		int i;
		for(i=0;i<size && *p != '\r';i++,p++)
			buf[i]=*p;
		buf[i]='\0';
		if(i == size)buf[i-1]='\0';
		data[len-1]=tmp;
		return buf;
}
	/*
	void leggi() {
				if(header.caplen < sizeof(struct ether_header) + sizeof(struct iphdr)+sizeof(struct tcphdr))return;
		        if(!isIPv4() || !isHTTP())return;
				const struct iphdr      *h_ip;
				struct ether_header* h_eth = (struct ether_header*)pkt_data;
		        h_ip = (const struct iphdr *) (pkt_data+sizeof(struct ether_header));

		        printf("\n----------- Ip packet ------------\n\n");
		        printf("Versione\t->\t%d\n", h_ip->version);
		        printf ("Ttl\t\t->\t%d\n", h_ip->ttl);
		        printf("Tos\t\t->\t%d\n", h_ip->tos);
		        struct in_addr in;
		        in.s_addr = h_ip->saddr;
		        printf("Ip source\t->\t%s\n", inet_ntoa(in));
		        in.s_addr = h_ip->daddr;
		        printf("Ip destination\t->\t%s\n\n", inet_ntoa(in));


		        struct tcphdr   *h_tcp;
		                int             i;

		                h_tcp = (struct tcphdr *) (pkt_data + sizeof(struct ether_header) + sizeof(struct iphdr));

		                printf("----------- TCP packet -----------\n\n");
		                printf("S. port\t\t->\t%d\n", ntohs(h_tcp->source));
		                printf("D. port\t\t->\t%d\n", ntohs(h_tcp->dest));
		                printf("Sequence number\t->\t%u\n", ntohl(h_tcp->seq));
		                printf("Ack number\t->\t%u\n", ntohl(h_tcp->ack_seq));
		                printf("Data offset\t->\t%d\n", h_tcp->doff * 4);
		                printf("Window\t\t->\t%d\n\n\n", ntohs(h_tcp->window));

		                printf("----------- DATI -----------\n\n");



		}
		*/
	/*
	 * 	/**
	inline char* getHttpHost(char* buf,const unsigned int BUFSIZE){
		char* data = getHttpDataPointer();
		int l = getHttpPayloadLenght();
		int i = 0;
		buf[BUFSIZ-1]='\0';
		for(;i<3;i++)
			buf[i]=data[i];
		buf[3]='\0';
		if(strstr(buf,"GET") == NULL){return NULL;}
		while(i<BUFSIZ && data[i]!='\0' && data[i] != '\r' && data[i] != '\n'){
			  buf[i]=data[i];
			  i++;
		}
		if(i<BUFSIZ)buf[i]='\0';
		std::cout << buf << std::endl;
		return buf;
	}
	 */
};


#endif

