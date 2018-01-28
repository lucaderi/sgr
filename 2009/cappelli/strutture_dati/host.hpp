/*
 * host.cpp
 * Fornisce l'oggetto di tipo host, con le sue informazioni, i get, i set e il print.
 */

#ifndef HOST_HPP_
#define HOST_HPP_

#include <iostream>
#include <stdlib.h>
#include <cstdio>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <boost/circular_buffer.hpp>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <boost/thread/xtime.hpp>
//#include <boost/thread/mutex.hpp>

using namespace std;

//offset
const int off_ip_data = 4; // inizio del payload del pacchetto ip (x word da 32 bit)
const int off_ip_protocol = 9; // Descrittore del protocollo di livello 4 incapsulato nel protocollo IP
const int off_ip_ipso = 12; // inizio ip sorgente del pacchetto ip
const int off_ip_ipdest = 16; // inizio ip destinazione del pacchetto ip

/*pacchetto TCP e UDP */
const int off_portdest = 2;
const int off_portsor = 0;
//Numero degli ultimi website-porte-protocolli ecc..
const int numberOfLast = 30;

// Protocollo livello applicazione
struct appProt
{
	string name;
	bool type; //true=tcp, false=udp
};

class host
{
private:
	struct in_addr iphost;
	u_char *machost; //se non � presente significa che � stato solo pingato ma non � stato catturato traffico
	string so, name; //Nome del sistema operativo e dell'host
	int soid; //id del sistema operativo
	int uptime;
	int lastboot;
	unsigned int lastseenalive; //u_int ricavato da xt.sec (secondi)
	bool port80;
	bool ssh;
	bool isgateway;
	bool inactive;
	string userAgent;


	//buffer circolari
	boost::circular_buffer<string> last_protocol_transp;
	//boost::mutex last_protocol_transp_mutex;
	boost::circular_buffer<appProt> last_protocol_app;
	//boost::mutex last_protocol_app_mutex;
	boost::circular_buffer<string> last_website;
	//boost::mutex last_website_mutex;

	//lista dele porte aperte
	vector<unsigned int> open_ports; //fino a 65535

public:
	host();
	~host();
	char* getIphostChar();
	struct in_addr getIp();
	void setIphost(struct in_addr iph);
	u_char * getMac();
	void setMac(u_char * mac);
	string getSo();
	void setSo(string so);
	string getHn();
	void setHn(string namein);
	bool getPort80();
	void setPort80(bool n);
	bool getSsh();
	void setSsh(bool n);
	bool getIsGateway();
	void setIsGateway(bool n);
	string getUserAgent();
	void setUserAgent(string ua);
	unsigned int getLastseenalive();
	void setLastseenalive(unsigned int lastseenalive);
	void setinactive(bool n);
	unsigned int getinactive();
	string* getLastTranspProtocols();
	void addLastTranspProtocol(string protocollo);
	appProt* getLastAppProtocols();
	void addLastAppProtocol(string protocollo, bool type);
	string* getLastWebsites();
	void addLastWebsite(string website);
	vector<unsigned int>* getOpenPorts();
	void addOpenPort(int portaaperta);
	//contrassegna gli host inattivi per pi� di maxinactiveTime
	void markIfinactive();
	void print();
	bool printJs(string& out);
};

#endif /* HOST_HPP_ */
