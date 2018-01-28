/*
 * @short whoml = what's happening on my lan
 * @author Federico Cappelli <cappellf@cli.di.unipi.it> <federico@federicocappelli.net>
 * @version alpha 1
 *
 * Lib terze parti:
 * - Libpcap
 * - Boost
 *
 * Tool unix usati per reperire info di rete:
 * - netstat
 * - fping
 * - arp
 * - nslookup
 * - nmblookup
 */

/*TODO
 * 1 - identificazione OS
 * 2 - Arp spooffing a richiesta
 * 3 - SNMP sul router, snmplink.org
 * 4 - implementare ricerca sniffer non-standalone - http://www.dia.unisa.it/~ads/corso-security/www/CORSO-0001/snifferPCAP/Documentazione/sniffer.htm
 */

#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <sys/types.h>
#include <pwd.h>
#include <netinet/if_ether.h>

//LINUX:
#include <netinet/ether.h>

#define __FAVOR_BSD //scelta della forma bsd per l'header tcp
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstdlib>
#include <fstream>
#include <signal.h>
#include <boost/thread.hpp>
#include <boost/thread/xtime.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition.hpp>
#include <boost/lexical_cast.hpp>
#include "strutture_dati/host.hpp"
#include "protocolswitch.hpp"
#include "strutture_dati/flussi.hpp"
#include "mongoose.h"

using namespace std;

//*********************************************

string version = "Alpha 1";

//dati vari lan
struct in_addr netmask;
short int byteSm; //numero di byte della subnet mask, servono per il memcmp tra ip
struct in_addr iplh; //ip del local host
struct in_addr gateway;
u_char * gatewaymac;
struct in_addr broadcast;
string localHostName;
char *interface_name;
int uid;
unsigned long int tot_byte_rete; //Byte trafficati sulla rete (totale)
unsigned long int pkt_tcp; //Totale pacchetti tcp catturati
unsigned long int pkt_udp; //Totale pacchetti udp catturati

pcap_t *in_pcap = NULL; //var apertura device
pcap_if_t *devices_list, *p; //lista dei device disponibili
struct pcap_pkthdr *header; //L'header che pcap estrae
const u_char *packet; //Il puntatore al pacchetto attuale
bool verbose;
char hname[256]; //nome localhost
u_int porta_webserver;
bool webser = false;
string absolutePath;

//Id thread
boost::thread::id id_cattura;
boost::thread::id id_elabora;

vector<host> vHost;
boost::mutex vhost_mutex; //Mutex su vHost

struct pacchetto
{
	u_char* p;
	u_int lung;
};

//buffer ciclico di pacchetti catturati
boost::circular_buffer<pacchetto> pkts(1000);
boost::mutex pkts_mutex; //Mutex su pkts

//mutex per il blocco sul buffer pkts se vuoto.
boost::mutex cond_mutex;
boost::condition cond;

//Struttura dati per i flussi della rete
flussi flussiLan;

short maschera1 = 15; //00001111 per ottenere solo la parte alta di un byte

//Gestione interruzioni
struct sigaction terminazione; //per richiesta terminazione
struct sigaction interruzione; //per richiesta terminazione da tastiera CTRL+C
struct sigaction segfault; //terminazione da segmentation fault

bool stop = false;
string * puntatoreTrim;

struct httphdr
{
	char host[30];
	char userAgent[30];
	string userAgentString;
	char os[40];
	httphdr()
	{
		strcpy(host, "UNKNOWN\0");
		strcpy(userAgent, "UNKNOWN\0");
		strcpy(os, "UNKNOWN\0");
	}
};

static void help()
{
	cout << "whoml -i <interface> [-w] [-v]" << endl;
	cout << "         -i <interface> | Interfaccia di ascolto" << endl;
	cout << "         -w abilita il webserver" << endl;
	cout << "         -v Modalita' verbosa" << endl;
	cout << "Esempio: whoml -i eth0 -w -v" << endl;
	cout << "to stop: ctrl + c and wait the termination." << endl;
	cout << endl;
	cout << "WHOML (what's happening on my lan) Version: " << version << endl;
	cout
			<< "Mostra un resoconto di cosa accade sulla rete Lan, informazioni su gli host presenti e su cosa fanno tramite interfaccia web (porta 8080)."
			<< endl;
	cout << "per ulteriori informazioni visitare http://www.federicocappelli.net/whoml/" << endl;
	cout << endl;
	exit(0);
}

//Gestione della terminazione
void termina(int ex)
{
	stop = true; //Faccio terminare i thread
	cout << "\nM - Termino" << endl;
}

//*****************************UTILITY**********************************************************
//elimina i caratteri
inline string trim(const string& o)
{
	puntatoreTrim = new string(o);
	const char* chars = "\n\t\v\f\r ";
	(*puntatoreTrim).erase((*puntatoreTrim).find_last_not_of(chars) + 1);
	(*puntatoreTrim).erase(0, (*puntatoreTrim).find_first_not_of(chars));
	return (*puntatoreTrim);
}

//Restituisce la stringa data come autput dal comando "cmd"
string getStdoutFromCommand(char * cmd)
{
	const int MAX_BUFFER = 256;
	string * data = new string();
	FILE *stream;
	char buffer[MAX_BUFFER];

	stream = popen(cmd, "r");
	while (fgets(buffer, MAX_BUFFER, stream) != NULL)
		(*data) = (*data).append(buffer);
	pclose(stream);
	return *data;
}

//Restituisce un vettore di stringhe contenente l'autput dal comando "cmd"
void getStdoutInVectorFromCommand(string cmd, vector<string>& data)
{
	const int MAX_BUFFER = 512;
	FILE *stream;
	char buffer[MAX_BUFFER];

	stream = popen(cmd.c_str(), "r");
	int i = 0;
	while (fgets(buffer, MAX_BUFFER, stream) != NULL)
	{
		string * tmp = new string(trim(buffer) + "\0");
		if (puntatoreTrim != NULL) delete puntatoreTrim;
		data.push_back(*tmp);
		i++;
	}
	pclose(stream);
}

//Divide la stringa passata come parametro prendendo come separatore "delimiters" e mette ogni token nel vettore "tokens"
void tokenize(const string& str, vector<string>& tokensout, const string& delimiters = " ")
{
	tokensout.clear();
	if (!str.empty())
	{
		string::size_type lastPos = str.find_first_not_of(delimiters, 0);
		string::size_type pos = str.find_first_of(delimiters, lastPos);

		while (string::npos != pos || string::npos != lastPos)
		{
			string * tmp = new string(str.substr(lastPos, pos - lastPos) + "\0");
			tokensout.push_back(*tmp);
			lastPos = str.find_first_not_of(delimiters, pos);
			pos = str.find_first_of(delimiters, lastPos);
		}
	}
}

//confronta 2 mac passati per argomento.
bool equalsMac(u_char * m1, u_char * m2)
{
	bool response = false;
	/*if (m1 != NULL && m2 != NULL && verbose)
	 {
	 cout << "Confronto : " << endl;
	 printf("%x:%x:%x:%x:%x:%x\n", m1[0], m1[1], m1[2], m1[3], m1[4], m1[5]);
	 cout << "con:" << endl;
	 printf("%x:%x:%x:%x:%x:%x\n", m2[0], m2[1], m2[2], m2[3], m2[4], m2[5]);
	 }*/
	if (m1 && m2)
	{
		response = !memcmp(m1, m2, 6);
		/*if (m1[0] == m2[0] && m1[1] == m2[1] && m1[2] == m2[2] && m1[3] == m2[3] && m1[4] == m2[4] && m1[5] == m2[5])
		 response = true;
		 else
		 response = false;*/
	}
	else
		cout << "  - Un puntatore a mac nullo" << endl;

	/*if (response)
	 cout << "uguali." << endl;
	 else
	 cout << "diversi." << endl;*/
	return response;
}

/*
 * Confronta il mac m con i mac riservati ai protocolli o il mac di broadcast
 * return true se il mac e' diverso da tutti queli non validi, false altrimenti
 *
 * nota: http://www.iana.org/assignments/ethernet-numbers
 */
bool validateMac(u_char * m)
{
	//se il 1' bit del mac e' 1 allora e' di broadcast/multicast
	//1:80:c2:0:0:ecc - IEEE Std 802.1D and IEEE Std 802.1Q reserved addresses
	u_char reserved1[5] =
	{ 0x1, 0x80, 0xc2, 0x0, 0x0 };
	// 01:00:5e ecc.. multicast ethernet
	u_char reserved2[3] =
	{ 0x1, 0x00, 0x5e };
	//ff:ff:ff:ff:ff:ff -  broadcast
	u_char broadcast[6] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	//printf("validazione: ---------%x:%x:%x:%x:%x:%x\n", m[0], m[1], m[2], m[3],m[4], m[5]);

	if (memcmp(m, reserved1, 5) != 0 && memcmp(m, broadcast, 6) != 0 && memcmp(m, reserved2, 3) != 0)
	{
		//if (verbose) cout << "mac valido." << endl;
		return true;
	}
	else
	{
		//if (verbose) cout << "mac non valido." << endl;
		return false;
	}
}

/*
 * Return true: ippar e' della stessa subnet dell'ip del local host es: 10.0.0.1 e 10.0.0.22 -> 10.0.0.0\24
 * Return false: ip esterno
 *
 * Notare: nota: http://www.iana.org/assignments/ethernet-numbers
 */
bool validateIp(struct in_addr ippar)
{
	if (memcmp(&ippar, &iplh, byteSm) == 0) //confronto i primi byteSm bit, a seconda della subnet mask

	{
		if (verbose) cout << "  - ip (" << inet_ntoa(ippar) << ") valido." << endl;
		return true;
	}
	else
	{
		if (verbose) cout << "  - ip  (" << inet_ntoa(ippar) << ") esterno." << endl;
		return false;
	}
}

/*
 * Tenta di tradurre l'ip passato come parametro nel nome dell'host se riesce restituisce il nome, altrimenti una stringa vuota ("")
 */
char * resolvename(char * ip)
{
	char * name = NULL;
	bool notfound = true;
	if (false)//notfound)

	{
		struct in_addr ip_inaddr;
		if (!inet_aton(ip, &ip_inaddr))
		{
			if (verbose) cout << "R - Conversione ip in in_addr fallita, ip:" << inet_ntoa(ip_inaddr) << endl;
		}
		else
		{
			struct hostent *he = new struct hostent();
			he = gethostbyaddr((const void *) &ip_inaddr, sizeof ip_inaddr, AF_INET);
			if (he != NULL)
			{
				//name = new char[50];
				//sprintf(name, "%s", he->h_name);
				int size = sizeof(he->h_name);
				char * temp = new char[size + 1];
				memcpy(temp, he->h_name, size + 1);
				sprintf(temp, "%s", temp);
				name = temp;
				notfound = false;
				string namestring = string(name);
				if (verbose) cout << "R - Ip: " << ip << " risoluzione nome con gethostbyaddr: " << namestring << endl;
				delete he;
			}
			else if (verbose) herror("R - Errore risoluzione nome con gethostbyaddr");//cout << "R - Errore risoluzione nome con gethostbyaddr: " << h_errno << endl;
		}
	}

	//Ricerca nome con nslookup
	if (notfound)
	{
		vector<string> autputns = vector<string> ();
		vector<string> tokensns = vector<string> ();

		//nslookup 131.114.11.16
		string cmd = "nslookup ";
		cmd = cmd.append(ip);
		getStdoutInVectorFromCommand(cmd, autputns);

		if (autputns.size() > 3)
		{
			tokenize(autputns.at(4), tokensns);

			if (tokensns.size() > 2 && tokensns.at(1).compare("=") == 0)
			{
				int size = trim(tokensns.at(2)).size();
				if (puntatoreTrim != NULL) delete puntatoreTrim;
				//char * temp = new char[size + 1];
				name = new char[size + 1];
				memcpy(name, trim(tokensns.at(2)).c_str(), size + 1);
				if (puntatoreTrim != NULL) delete puntatoreTrim;
				sprintf(name, "%s", name);
				//name = temp;
				//sprintf(name, "%s", (*tokensns).at(2).c_str());
				notfound = false;
				string namestring = string(name);
				if (verbose) cout << "R - Ip: " << ip << " risoluzione nome con NSLOOKUP: " << namestring << endl;
			}
		}

		/*Risposta affermativa:
		 Server:		131.114.120.2
		 Address:	131.114.120.2#53

		 Non-authoritative answer:
		 16.11.114.131.in-addr.arpa	name = oracle2.cli.di.unipi.it.

		 Authoritative answers can be found from:
		 11.114.131.in-addr.arpa	nameserver = ns2.cli.di.unipi.it.
		 11.114.131.in-addr.arpa	nameserver = nameserver.cli.di.unipi.it.
		 11.114.131.in-addr.arpa	nameserver = nameserver.di.unipi.it.
		 ns2.cli.di.unipi.it	internet address = 131.114.120.2
		 nameserver.di.unipi.it	internet address = 131.114.3.6
		 nameserver.cli.di.unipi.it	internet address = 131.114.11.37

		 *negativa:
		 Server:		131.114.120.2
		 Address:	131.114.120.2#53

		 ** server can't find 131.114.11.298: NXDOMAIN
		 */
	}

	if (notfound)
	{
		vector<string> autputnmp;// = vector<string> ();
		vector<string> tokensnmb;// = vector<string> ();
		vector<string> tokensnmb2;// = vector<string> ();
		//nmblookup -A 192.168.100.46
		/*
		 * fail:
		 0 Looking up status of 192.168.100.23|
		 1 No reply from 192.168.100.23|
		 2  |
		 *
		 *succes:
		 0 Looking up status of 192.168.100.32|
		 1 PC-ALESSANDRO   <00> -         B <ACTIVE>|
		 2 WORKGROUP       <00> - <GROUP> B <ACTIVE>|
		 3 PC-ALESSANDRO   <20> -         B <ACTIVE>|
		 4 WORKGROUP       <1e> - <GROUP> B <ACTIVE>|
		 5  |
		 6 MAC Address = 00-16-EA-28-38-F2|
		 7  |
		 */
		string cmd;
		cmd.assign("nmblookup -A ");
		cmd = cmd.append(ip);
		getStdoutInVectorFromCommand(cmd, autputnmp);
		tokenize(autputnmp.at(1), tokensnmb);
		if (tokensnmb.size() > 0 && tokensnmb.at(0).compare("No") != 0)
		{
			tokenize(autputnmp.at(1), tokensnmb2);
			int size = trim(tokensnmb2.at(0)).size();
			if (puntatoreTrim != NULL) delete puntatoreTrim;
			char * temp = new char[size + 1];
			memcpy(temp, trim(tokensnmb2.at(0)).c_str(), size + 1);
			if (puntatoreTrim != NULL) delete puntatoreTrim;
			sprintf(temp, "%s", temp);
			name = temp;

			//name = new char[50];
			//sprintf(name, "%s", (*tokensnmb2).at(0).c_str());
			//(*name).assign((*tokensnmb2).at(0));
			notfound = false;
			string namestring = string(name);
			if (verbose) cout << "R - Ip: " << ip << " risoluzione nome con NMBLOOKUP: " << namestring << endl;
		}
		autputnmp.clear();
		tokensnmb.clear();
		tokensnmb2.clear();
	}

	//Ricerca nome host con Bonjour (zeroconf), usare avahi
	//TODO mostrare anche risorse pubblicate con bonjour
	if (notfound)
	{

	}

	//Todo Ricerca nome host con WINS per windows,
	if (notfound)
	{

	}
	//if (verbose) cout << "R - Ip: " << ip << " Name: " << name << endl;
	if (name == NULL)
	{
		name = new char[3];
		sprintf(name, "?");
	}

	return name;
}

//Dato l'ip restituisce un puntatore a un array di u_char contenente il mac, usando arp
void iptomac(struct in_addr ip, u_char * out)
{
	/*
	 arp 192.168.100.73
	 ? (192.168.100.73) at 0:13:77:bd:7a:92 on en1 ifscope [ethernet]
	 */
	/*string tmp = inet_ntoa(ip);
	 string cmd = "arp " + tmp;*/
	struct ether_addr * aaa = new ether_addr();
	char cmd[100];
	sprintf(cmd, "arp %s", inet_ntoa(ip));
	string outarp = getStdoutFromCommand(cmd);
	vector<string> tokenarp;
	tokenize(outarp, tokenarp);
	if (tokenarp.size() > 2 && tokenarp.at(3).size() >= 7)
	{
		string my_string;
		my_string = my_string.assign(tokenarp.at(3));
		if (verbose) cout << "  - Mac risolto: " << my_string << endl;
		memcpy(aaa, ether_aton(my_string.c_str()), sizeof(aaa));//aaa = ether_aton(my_string.c_str());
		tokenarp.clear();
		//MACOSX=
		//memcpy(out, aaa->octet, ETHER_ADDR_LEN);

		//LINUX=
		memcpy(out, aaa->ether_addr_octet, ETHER_ADDR_LEN);
	}
	else
		cout << "IP to mac fallito" << endl;
	delete aaa;
}

//Ritorna true se il file esiste false altrimenti
bool fileExist(char * filename)
{

	if (strlen(filename) <= 0) return false;
	FILE *f = fopen(filename, "r");
	if (f)//Il file esiste.

	{
		fclose(f);
		return true;
	}
	return false;
}

//Fa il parsing di un messaggio http e inserisce host e user agent nella struct httphdr, ritorna il puntatore a questa struct, altrimenti NULL
struct httphdr * parseHttp(char * msg)
{
	//Scompongo il messagio http e ricavo l'host
	char *word, *phrase, *brkt, *brkb;
	bool hostfound = false;
	bool uafound = false;
	struct httphdr * hdr = new httphdr();
	//string * useragentstring = new string();
	//char useragentstring[300] = "";
	string useragentstring;
	if (msg != NULL)
	{
		int i = 0;
		for (phrase = strtok_r(msg, "\n", &brkt); phrase; phrase = strtok_r(NULL, "\n", &brkt))
		{
			//printf("parsehttp| riga: %s\n", phrase);
			int j = 0;
			for (word = strtok_r(phrase, " ", &brkb); word; word = strtok_r(NULL, " ", &brkb))
			{
				//printf("parsehttp| ---- parola: %s\n", word);
				if (i == 0 && j == 0 && strcmp(word, "GET") != 0) return NULL; //Non ÔøΩ una GET
				if (strcmp(word, "Cache-Control:") == 0 || strcmp(word, "Accept:") == 0 || strcmp(word, "Accept-Language:") == 0 || strcmp(word,
						"Accept-Encoding:") == 0 || strcmp(word, "Referer:") == 0 || strcmp(word, "Authorization:") == 0 || (uafound && strcmp(word,
						"Host:") == 0))
				{
					uafound = false;
					//sprintf(hdr->userAgentString, "%s", trim(string(useragentstring)).c_str());
					hdr->userAgentString.assign(trim(useragentstring));
					if (puntatoreTrim != NULL) delete puntatoreTrim;
				}

				if (hostfound)
				{
					//TODO: Stampo solo il dominio di 1' livello. ???
					sprintf(hdr->host, "%s", trim(word).c_str());
					if (puntatoreTrim != NULL) delete puntatoreTrim;
					hostfound = false;
				}

				if (uafound)
				{
					//sprintf(useragentstring, "%s %s", useragentstring, word);
					useragentstring = useragentstring.append(" ");
					useragentstring = useragentstring.append(word);
				}
				if (strcmp(word, "Host:") == 0) hostfound = true;
				if (strcmp(word, "User-Agent:") == 0) uafound = true;
				j++;
			}
			uafound = false;
			hostfound = false;
			i++;
		}
		if (strcmp(hdr->host, "") != 0 && strcmp(hdr->host, "UNKNOWN") != 0)
		{
			if (verbose)
			{
				if (verbose) cout << "parsehttp: host:" << hdr->host << endl;
				if (verbose) cout << "parsehttp: user agent string:" << hdr->userAgentString << endl;
			}
			return hdr;
		}
		else
			return NULL;
	}
	else
		return NULL;
}

//************************ FINE UTILITY ***********************
/*
 * Cattura i pacchetti dall'interfaccia di rete e li inserisce nella struttura dati condivisa.
 */
void cattura()
{
	id_cattura = boost::this_thread::get_id();
	if (verbose) cout << "C - cattura thread started." << endl;
	int next;
	while (!stop && (next = pcap_next_ex(in_pcap, &header, &packet)) >= 0) //se non ho pacchetti return = 0
	{
		if (next == 1) //pacchetto catturato
		{
			u_char * t = new u_char[header->caplen + 1]; //nuovo puntatore ad area di memoria con spazio per il pacchetto
			//riverso il pacchetto nella nuova area di memoria
			for (u_int y = 0; (y <= header->caplen); y++)
			{
				t[y] = packet[y];
			}
			tot_byte_rete = header->caplen + tot_byte_rete;
			pacchetto pkt;
			pkt.p = t;
			pkt.lung = header->caplen;
			//immagazzina dentro struttura dati di u_char condivisa
			boost::mutex::scoped_lock lock(pkts_mutex);
			pkts.push_back(pkt);

			//notifico al thread elabora che il buffer non è vuoto
			boost::mutex::scoped_lock lock2(cond_mutex);
			cond.notify_all();
			//cout << "pacchetto arrivato, sveglio threar." << endl;

			lock.unlock();
		}
	}
	if (verbose) cout << "C - packet capturing error OR thread cattura stoped." << endl;
}

/*
 * analizza i pacchetti presi dal buffer, inserisce i dati nelle varie strutture dati, cancella i pacchetti processati.
 */
void elabora()
{
	if (verbose) cout << "E - elabora thread started." << endl;
	id_elabora = boost::this_thread::get_id();
	/*
	 Livelli di rete:
	 Livello di applicazione - Dns, HTTP ecc...
	 6 	Livello di presentazione - trasformazione
	 5 	Livello di sessione - ssh, scp, NetBios
	 4 	Livello di trasporto - Tcp, Udp, ecc.
	 3 	Livello di rete - IpV4, IpV6
	 2 	Livello Data Link - Ethernet, IEE 802.11, ppp ecc
	 1 	Livello fisico - non ci interessa
	 */

	int off_data; //lunghezza header Ethernet quindi inizio dati Ip in byte
	int lung_header_ip; //lunghezza header Ip
	u_short lung_ip; //lunghezza intero pacchetto ip in byte
	struct ip headerip;

	struct in_addr mittente;
	struct in_addr destinatario;
	struct ether_header *ether;
	struct httphdr * http;
	pkt_tcp = 0;
	pkt_udp = 0;

	//capisco che tipo di DataLink sto usando e regolo i vari offset di conseguenza
	int link_layer;

	link_layer = pcap_datalink(in_pcap);
	switch (link_layer)
	{
	case DLT_EN10MB: // Ethernet II
		off_data = 14; //byte, il 14ÔøΩ byate e' il primo del payload ethernet
		if (verbose) cout << "E - Link = Ethernet." << endl;
		break;
	case DLT_IEEE802_11: // Wi-fi 802.11
		off_data = 20;
		if (verbose) cout << "E - Link = Wi-fi 802.11." << endl;
		break;
	default:
		cout << "E - Link type [" << link_layer << "] not supported, connect with Ethernet or 802.11 (Wi-fi)." << endl;
		exit(1);
	}

	u_char * tmppkt; //var temp per il pacchetto che analizzo
	bool nuovo = true;
	bool nuovoDest = true;
	struct tcphdr headertcp;
	struct udphdr headerudp;
	int portaTcpMit;
	int portaTcpDes;
	unsigned int data_offset; //inizio payload tcp
	int portaUdpMit;
	int portaUdpDes;
	boost::xtime xt; //tempo
	int protocollolvl5;
	u_int lunghezza_pacchetto;

	//analizzo i pacchetti presenti nel buffer circolare con un ciclo attivo
	while (!stop)
	{
		if (!pkts.empty()) //Buffer di cattura non vuoto
		{
			boost::mutex::scoped_lock lock(pkts_mutex);
			//tmppkt = new u_char[sizeof(pkts[0])];
			tmppkt = pkts[0].p;
			lunghezza_pacchetto = pkts[0].lung;
			pkts.pop_front(); //elimino il puntatore a pacchetto in testa
			lock.unlock();
			if (verbose) cout << "E - processing package. (packet left=" << pkts.size() << ")." << endl;
			if (verbose) cout << "E - dimensione vhost: " << vHost.size() << endl;

			//*** ANALISI CONTENUTO PACCHETTO *****************************************************************************************************************
			ether = (struct ether_header*) (tmppkt); //copio il pacchetto nella struttura dell'header ethernet

			//analisi protocollo di livello traspoto (4'), tratto solo IPv4
			if (ntohs (ether->ether_type) == ETHERTYPE_IP)
			{
				memcpy(&headerip, &tmppkt[off_data], sizeof(struct ip));
				mittente = headerip.ip_src;
				destinatario = headerip.ip_dst;
				lung_ip = headerip.ip_len;

				protocollolvl5 = (int) headerip.ip_p; //tmppkt[off_data + 9]; //protocollo incapsulato
				//memcpy(&protocollolvl5, &headerip.ip_p, sizeof(headerip.ip_p));

				if (verbose)
				{
					cout << "E - Pacchetto catturato: " << inet_ntoa(mittente);
					cout << " ----> " << inet_ntoa(destinatario);
					cout << " | Prot: " << protocollolvl5;
					cout << " CIOE': " << protIdtoName(protocollolvl5) << endl;
				}

				//analizzo il protocollo a livello applicazione (5'), analizzo solo l'interno di TCP e UDP
				lung_header_ip = maschera1 & tmppkt[off_data]; //prendo 1Byte = 8 bit ma me ne servono solo 4
				lung_header_ip = lung_header_ip * 4; //in byte

				//Aggiungo il flusso
				if (protocollolvl5 == 6) //tcp
				{
					pkt_tcp++;
					memcpy(&headertcp, &tmppkt[off_data + lung_header_ip], sizeof(struct tcphdr)); //20 byte lunghezza minima header tcp, 16 lunghezza che mi serve
					portaTcpDes = ntohs(headertcp.th_dport);
					portaTcpMit = ntohs(headertcp.th_sport);
					data_offset = headertcp.th_off * 4; //inizio (in byte) payload rispetto all'inizio del pacchetto tcp
					//Controllo se syn (addFlux), fin (delFlux) o ack (incrFlux)
					if (headertcp.th_flags == TH_SYN)
					{
						if (verbose) cout << "E - Flusso tcp SYN" << endl;
						flussiLan.addFlux(mittente, destinatario, portaTcpMit, portaTcpDes, true);
					}
					else if (headertcp.th_flags == TH_FIN) //TODO controllare, aggiungere reset

					{
						if (verbose) cout << "E - Flusso tcp FIN" << endl;
						//flussiLan.deleteFlux(mittente, destinatario, portaTcpMit, portaTcpDes, true);
						flussiLan.setTerminato(mittente, destinatario, portaTcpMit, portaTcpDes, true);
					}
					else if (headertcp.th_flags == TH_ACK)
					{
						if (verbose) cout << "E - Flusso tcp ACK" << endl;
						flussiLan.incrementFlux(mittente, destinatario, portaTcpMit, portaTcpDes, true);
					}
					else
					{
						if (verbose) cout << "E - Flusso tcp non identificato" << endl;
						flussiLan.incrementFlux(mittente, destinatario, portaTcpMit, portaTcpDes, true);
					}

					//Analizza HTTP alla ricerca dell'host e dell'user agent
					if (portaTcpDes == 80)
					{
						//trovo lunghezza pacchetto http
						u_int lung = lunghezza_pacchetto - (off_data + lung_header_ip + data_offset);
						//cout << "LUNGHEZZA HTTP: " << lung << endl;
						if (lung > 0)
						{
							char tcppayload[lung];
							if (verbose) cout << "E - Analizzo possibile messaggio http." << endl;
							memcpy(&tcppayload, &tmppkt[off_data + lung_header_ip + data_offset], lung);
							tcppayload[lung - 1] = '\0';
							//cout << "Test http - payload:" << tcppayload << "|" << endl;
							//Scompongo il messagio http e ricavo l'host
							http = parseHttp(tcppayload);
						}
					}
				}
				else if (protocollolvl5 == 17) //udp

				{
					pkt_udp++;
					memcpy(&headerudp, &tmppkt[off_data + lung_header_ip], 8); //8 byte lunghezza header udp
					portaUdpDes = ntohs(headerudp.uh_dport);
					portaUdpMit = ntohs(headerudp.uh_sport);
					//Incremento sempre il flusso udp anche se non e' presente, il metodo si occupa di tutto
					flussiLan.incrementFlux(mittente, destinatario, portaUdpMit, portaUdpDes, false);
				}

				//*** IDENTIFICO HOST E INSERISCO I DATI *****************************************************************************************************************

				u_int i = 0;
				boost::xtime_get(&xt, boost::TIME_UTC);
				boost::mutex::scoped_lock lock(vhost_mutex); //Blocco il mutex
				u_int vhostsize = vHost.size();
				//Cerco il mittente e il destinatario del pacchetto tra gli host conosciuti in vHost
				while (i < vhostsize)// && (nuovo || nuovoDest))
				{
					//mittente identificato in vhost
					if (nuovo && equalsMac(vHost[i].getMac(), ether->ether_shost))
					{
						//aggiungo i dati raccolti
						if (verbose) cout << "Host mittente gia' conosciuto, aggiorno" << endl;
						vHost[i].setLastseenalive((u_int) xt.sec);
						vHost[i].setinactive(false);
						if (!vHost[i].getIsGateway())
						{
							vHost[i].setIphost(mittente); //aggiungo l'ip al mittente
							//aggiungo agli ultimi 10 protocolli di trasporto usati il prot. incapsulato nell'ip
							string nomeprot;
							nomeprot = nomeprot.assign(protIdtoName(protocollolvl5));
							vHost[i].addLastTranspProtocol(nomeprot); //tcp, udp ecc.
							if (http && portaTcpDes == 80)
							{
								vHost[i].addLastWebsite(http->host);
								if (http->userAgentString.size() > 1) vHost[i].setUserAgent(http->userAgentString);
								http = NULL;
							}
							//se ip mttente = ip localhost inserisco anche il nome
							if (mittente.s_addr == iplh.s_addr) vHost[i].setHn(localHostName);
						}
						nuovo = false;
					}
					else
					{
						//destinatario identificato in vhost
						if (nuovoDest && equalsMac(vHost[i].getMac(), ether->ether_dhost))
						{
							if (verbose) cout << "Host Destinatario gia' conosciuto, aggiorno" << endl;
							//vHost[i].setLastseenalive((u_int) xt.sec);
							//vHost[i].setinactive(false);
							if (!vHost[i].getIsGateway())
							{
								vHost[i].setIphost(destinatario); //aggiungo l'ip al destinatario
								//aggiungo agli ultimi 10 protocolli di trasporto usati il prot. incapsulato nell'ip
								string nomeprot;
								nomeprot = nomeprot.assign(protIdtoName(protocollolvl5));
								vHost[i].addLastTranspProtocol(nomeprot); //tcp, udp ecc.
								//se ip mttente = ip localhost inserisco anche il nome
								if (destinatario.s_addr == iplh.s_addr) vHost[i].setHn(localHostName);
							}
							nuovoDest = false;
						}
					}
					i++;
				}

				//l'host corrispondente al mac sorgente non e' giÔøΩ presente, lo aggiungo
				boost::xtime_get(&xt, boost::TIME_UTC);
				if (nuovo && validateMac(ether->ether_shost) && validateIp(mittente))
				{
					host nuovoHost = host();
					nuovoHost.setMac(ether->ether_shost); //inserisco il mac sorgente
					nuovoHost.setLastseenalive((u_int) xt.sec);
					nuovoHost.setinactive(false);

					//Confronta il mac del gateway con l'host alla ricerca del router/gateway
					if (equalsMac(gatewaymac, ether->ether_shost))
					{
						nuovoHost.setIphost(gateway); //aggiungo l'ip del gateway
						nuovoHost.setIsGateway(true);
						nuovoHost.setHn("Gateway/Router");
						if (verbose) cout << "E - L'host mittente e' il Gateway/Router" << endl;
					}
					else
					{
						nuovoHost.setIphost(mittente); //aggiungo l'ip al mittente
						//aggiungo agli ultimi 10 protocolli di trasporto usati il prot. incapsulato nell'ip
						nuovoHost.addLastTranspProtocol(protIdtoName(protocollolvl5)); //tcp, udp ecc.
						if (http && portaTcpDes == 80)
						{
							nuovoHost.addLastWebsite(http->host);
							if (http->userAgentString.size() > 1) nuovoHost.setUserAgent(http->userAgentString);
							http = NULL;
						}

						//se ip mttente = ip localhost inserisco anche il nome
						if (mittente.s_addr == iplh.s_addr) nuovoHost.setHn(localHostName);
					}
					if (verbose) cout << "E - Nuovo host (mittente) trovato, lo aggiungo." << endl;
					//Inserisco l'host nel vHost
					if (verbose) nuovoHost.print();
					vHost.push_back(nuovoHost);
				}

				//l'host corrispondente al mac destinatario non e' giÔøΩ presente, lo aggiungo
				if (nuovoDest && validateMac(ether->ether_dhost) && validateIp(destinatario))
				{
					host nuovoHostDest = host();
					nuovoHostDest.setMac(ether->ether_dhost); //inserisco il mac destinazione
					nuovoHostDest.setLastseenalive((u_int) xt.sec);
					nuovoHostDest.setinactive(false);

					//Confronta il mac del gateway con l'host alla ricerca del router/gateway
					if (equalsMac(gatewaymac, ether->ether_dhost))
					{
						nuovoHostDest.setIphost(gateway); //aggiungo l'ip del gateway
						nuovoHostDest.setIsGateway(true);
						nuovoHostDest.setHn("Gateway/Router");
						if (verbose) cout << "E - L'host destinatario e' il Gateway/Router" << endl;
					}
					else
					{
						nuovoHostDest.setIphost(destinatario); //aggiungo l'ip al destinatario
						//aggiungo agli ultimi 10 protocolli di trasporto usati il prot. incapsulato nell'ip
						nuovoHostDest.addLastTranspProtocol(protIdtoName(protocollolvl5)); //tcp, udp ecc.
						//se ip destinatario = ip localhost inserisco anche il nome
						if (destinatario.s_addr == iplh.s_addr) nuovoHostDest.setHn(localHostName);
					}
					if (verbose) cout << "E - Nuovo host (destinatario) trovato, lo aggiungo." << endl;
					if (verbose) nuovoHostDest.print();
					//Inserisco l'host nel vHost
					vHost.push_back(nuovoHostDest);
				}

				lock.unlock(); //Sblocco il mutex
				//-----------
			}//if IP

			else
			{
				u_short tipo = ether->ether_type;

				switch (tipo)
				{
				case ETHERTYPE_PUP:
					if (verbose) cout << "E - Protocollo lvl 4 (PUP) non supportato" << endl;
					break;

				case ETHERTYPE_ARP:
					if (verbose) cout << "E - Protocollo lvl 4 (ARP) non supportato" << endl;
					break;

				case ETHERTYPE_REVARP:
					if (verbose) cout << "E - Protocollo lvl 4 (REVARP) non supportato" << endl;
					break;

				case ETHERTYPE_VLAN:
					if (verbose) cout << "E - Protocollo lvl 4 (IEEE 802.1Q VLAN tagging) non supportato" << endl;
					break;

				case ETHERTYPE_IPV6:
					if (verbose) cout << "E - Protocollo lvl 4 (IPV6) non supportato" << endl;
					break;

				case ETHERTYPE_LOOPBACK:
					if (verbose) cout << "E - Protocollo lvl 4 (LOOPBACK) non supportato" << endl;
					break;
				}
			}//else if IP
		}
		else //if pkts vuoto
		{
			boost::mutex::scoped_lock lock(cond_mutex);
			cond.wait(lock);
		}
		nuovo = true;
		nuovoDest = true;
	}//while
	if (verbose) cout << "E - thread elabora stoped." << endl;
}

/*
 * Scansiona attivamente la rete alla ricerca degli host attivi e del loro nome.
 */
void activescan()
{
	if (verbose) cout << "A - thread Activescan started." << endl;
	//CI: dare la possibilitÔøΩ di aggiornare manualmente da GUI
	int waitSecs = 20; //secondi di sleep del thread
	boost::xtime xt; //tempo
	vector<string> ipAttivi = vector<string> ();

	while (!stop)
	{
		//Ping a tutti gli ip dela rete, poi confronto il risultato con gli host, quelli che ho pingato ma non ho in vHost gli aggiungo
		string ipstring;
		vector<string> tokens;
		tokenize(inet_ntoa(iplh), tokens, ".");
		ipstring = tokens.at(0) + "." + tokens.at(1) + "." + tokens.at(2) + ".1";
		//converto l'intero della subnetmask in string
		string sm = boost::lexical_cast<string>(byteSm * 8);

		//fping -ag -i15 -p500 -r1 131.114.252.1/24  2>/dev/null
		string cmd = "fping -ag -i15 -p500 -r1 " + ipstring + "/" + sm + " 2>/dev/null"; //comando per ottenere la linea di output di fping che mi interessa
		if (verbose) cout << "A - Eseguo " << cmd << endl;
		//Inserisce in ipAttivi l'autput dal comando "cmd"
		const int MAX_BUFFER = 256;
		FILE *stream;
		char buffer[MAX_BUFFER];
		stream = popen(cmd.c_str(), "r");
		int i = 0;
		while (fgets(buffer, MAX_BUFFER, stream) != NULL)
		{
			tokenize(trim(buffer), tokens);
			if (puntatoreTrim != NULL) delete puntatoreTrim;
			if (tokens.size() > 0)
			{
				string ip;
				ip = ip.assign(tokens.at(0));
				tokenize(ip, tokens, ".");
				if (tokens.at(3).compare("255")) //ip di multicast (se ==0 sono uguali e non fa l'if)

				{
					ipAttivi.push_back(ip + "\0");
				}
			}
			tokens.clear();
			i++;
		}
		pclose(stream);
		tokens.clear();
		//Fine

		//Aggiorno la variabile temporale
		boost::xtime_get(&xt, boost::TIME_UTC);
		//aggiorno gli host conosciuti e ricavo i nomi
		u_int j = 0;
		bool presente;
		string iphost;
		string nome;
		while (j < ipAttivi.size() && !stop)
		{
			presente = false;
			//cout << "TEST -" << trim(ipAttivi.at(j)) << "|" << endl;
			u_int h = 0;
			while (h < vHost.size() && !presente && !stop)
			{
				iphost = vHost.at(h).getIphostChar();
				if (iphost.compare(ipAttivi.at(j)) == 0) //trovato

				{
					boost::mutex::scoped_lock lock(vhost_mutex);
					vHost.at(h).setLastseenalive((u_int) xt.sec);
					vHost.at(h).setinactive(false);
					lock.unlock();
					if (vHost.at(h).getHn().compare("UNKNOWN") == 0)
					{
						if (verbose) cout << "A - Nome sconosciuto, tento di risolverlo." << endl;
						//Inserisco il nome se risponde a resolvename
						nome = nome.assign(resolvename((char *) (ipAttivi.at(j).c_str())));
						if (nome.compare("?") != 0)
						{//ha risposto
							boost::mutex::scoped_lock lock(vhost_mutex);
							vHost.at(h).setHn(nome);
						}
					}
					presente = true;
					if (verbose) cout << "A - Aggiornato host pingato (" << iphost << ")" << endl;
				}
				h++;
			}
			if (!presente)
			{
				host nuovoHost = host();
				//Inserisco il nome se risponde a resolvename
				nome = nome.assign(resolvename((char *) (ipAttivi.at(j).c_str())));
				if (nome.compare("?") != 0) //ha risposto
				{
					boost::mutex::scoped_lock lock(vhost_mutex);
					nuovoHost.setHn(nome);
				}
				//Aggiungo nuovo host
				in_addr ip;
				inet_aton(ipAttivi.at(j).c_str(), &ip);
				nuovoHost.setIphost(ip);
				nuovoHost.setLastseenalive((u_int) xt.sec);
				//Inserisco il MAC
				u_char * m = new u_char[16];
				iptomac(ip, m);
				nuovoHost.setMac(m);

				if (verbose) cout << "A - Aggiunto nuovo host pingato (" << ipAttivi.at(j) << ")" << endl;
				if (verbose) nuovoHost.print();
				boost::mutex::scoped_lock lock(vhost_mutex);
				vHost.push_back(nuovoHost);
			}
			j++;
			nome.clear();
			iphost.clear();
		}
		ipAttivi.clear();
		//metto in pausa il thread per $waitSecs secondi
		if (verbose) cout << "A - thread Activescan sleep for " << waitSecs << " sec." << endl;
		sleep(waitSecs);
	}

	if (verbose) cout << "A - thread Activescan stoped." << endl;
}

/*
 * Scansiona flussiLan e:
 * - Aggiorna i protocolli dell'host.
 * - Marca gli host inattivi.
 */
void updateflux()
{
	if (verbose) cout << "U - Thread updateflux started." << endl;
	int waitSecs = 30; //secondi di sleep del thread
	//boost::xtime xt; //tempo
	vector<unsigned int> porteTcp = vector<unsigned int> ();
	vector<unsigned int> porteUdp = vector<unsigned int> ();

	while (!stop)
	{
		for (u_int i = 0; i < vHost.size(); i++)
		{
			boost::mutex::scoped_lock lock(vhost_mutex);
			host temp = vHost[i];
			lock.unlock();
			temp.markIfinactive();
			if (!temp.getIsGateway())
			{
				flussiLan.hostPortsTcp(temp.getIp(), &porteTcp);
				flussiLan.hostPortsUdp(temp.getIp(), &porteUdp);
				//scorro i vettori delle porte e ricavo i protocolli, aggiungendoli all'host
				for (unsigned int j = 0; j < porteTcp.size(); j++)
				{
					unsigned int porta = porteTcp[j];
					//cout << "U - porta tcp: " << porta << endl;
					temp.addLastAppProtocol(portToProtocoll(porta), true);
				}
				//cout << "U - Host " << temp.getIphostChar() << " Trovate N' porte TCP: " << porteTcp.size() << endl;
				for (unsigned int h = 0; h < porteUdp.size(); h++)
				{
					unsigned int porta = porteUdp[h];
					//cout << "U - porta udp: " << porta << endl;
					temp.addLastAppProtocol(portToProtocoll(porta), false);
				}
				//cout << "U - Host " << temp.getIphostChar() << " Trovate N' porte UDP: " << porteUdp.size() << endl;
				boost::mutex::scoped_lock lock2(vhost_mutex);
				vHost[i] = temp;
				lock2.unlock();
			}
		}
		porteTcp.clear();
		porteUdp.clear();

		//Elimina i flussi udp troppo vecchi
		flussiLan.clearOldFlux();

		//metto in pausa il thread per $waitSecs secondi
		if (verbose) cout << "U - thread updateflux sleep for " << waitSecs << " sec." << endl;
		sleep(waitSecs);
		/*boost::xtime_get(&xt, boost::TIME_UTC);
		 xt.sec += waitSecs;
		 boost::thread::sleep(xt);*/
	}
	if (verbose) cout << "U - Thread updateflux stoped." << endl;
}

static void send_vhost_http(struct mg_connection *conn, const struct mg_request_info *request_info, void *user_data)
{
	string out = string();
	mg_printf(
			conn,
			"%s",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><META HTTP-EQUIV=\"CACHE-CONTROL\" CONTENT=\"NO-CACHE\"></head><body><h1>Struttura dati vHost (stringa JSON):</h1>");
	for (u_int i = 0; i < vHost.size(); i++)
	{
		vHost[i].printJs(out);
		mg_printf(conn, "%s", "<p>");
		boost::mutex::scoped_lock lock(vhost_mutex);
		mg_printf(conn, "%s", out.c_str());
		lock.unlock();
		mg_printf(conn, "%s", "</p>");
		out.clear();
	}
	mg_printf(conn, "%s", "</body>");
}

static void send_vhost_json(struct mg_connection *conn, const struct mg_request_info *request_info, void *user_data)
{
	string out = string();
	//Scrittura stringa JSON:
	string jsonString = string("{\"vhost\":[\0");

	boost::mutex::scoped_lock lock(vhost_mutex);
	if (vHost.size() > 0) //primo elemento senza ,
	{
		vHost[0].printJs(out);
		jsonString = jsonString.append(out);
	}
	out.clear();
	for (u_int i = 1; i < vHost.size(); i++)
	{
		jsonString = jsonString.append(",");
		vHost[i].printJs(out);
		jsonString = jsonString.append(out);
		out.clear();
	}
	jsonString = jsonString.append("]}\0");
	mg_write(conn, jsonString.c_str(), jsonString.size());
	lock.unlock();
	jsonString.clear();
}

static void terminate(struct mg_connection *conn, const struct mg_request_info *request_info, void *user_data)
{
	mg_printf(conn, "%s", "<h1>- Terminato -</h1>");
	termina(0);
}

/*
 * Lancia un webserver per rendere disponibili i dati catturati all'interfaccia web.

 void webserver()
 {
 int data = 1234567;
 struct mg_context *ctx;
 //boost::xtime xt; //tempo
 if (webser)
 {
 if (verbose) cout << "W - Webserver thread started." << endl;
 // http://code.google.com/p/mongoose/

 ctx = mg_start();
 mg_set_option(ctx, "ports", "8080");
 string wwwpath = absolutePath;
 wwwpath += "www/";
 //cout << "wwwpath: " << wwwpath << "|" << endl;
 mg_set_option(ctx, "root", wwwpath.c_str()); //imposto root
 mg_set_option(ctx, "index_files", "index.html");
 mg_set_uri_callback(ctx, "/vhost", &send_vhost, (void *) &data);
 //if (porta_webserver != 8080 && porta_webserver <= 65535 && porta_webserver > 0) mg_set_option(ctx, "ports", "8080");
 if (verbose) cout << "W - Porta webserver: " << porta_webserver << endl;

 while (!stop)
 sleep(1);
 }
 if (verbose) cout << "E - thread Webserver stoped." << endl;

 while (!stop)
 {
 //interfaccia temporanea, pre-CI

 //stampo tutti gli host:
 boost::mutex::scoped_lock lock(vhost_mutex);
 u_int vhostsize = vHost.size();
 lock.unlock();
 if (vhostsize > 0)
 {
 cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
 for (u_int i = 0; i < vhostsize; i++)
 {
 cout << "N' " << i << endl;
 boost::mutex::scoped_lock lock(vhost_mutex);
 vHost[i].print();
 }
 cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
 }
 flussiLan.print();
 //metto in pausa il thread
 boost::xtime_get(&xt, boost::TIME_UTC);
 xt.sec += 5;
 boost::thread::sleep(xt);
 }
 if (verbose) cout << "E - thread Webserver stoped." << endl;
 }
 */

/*
 * Abbandona i privilegi di root e torna nobody
 * //TODO Unico modo di implementare ÔøΩ creare un gruppo apposito per whoml e ritornarci una volta finita la parte da superuser.

 void changeUser()
 {
 struct passwd *pw = NULL;
 interface_name = NULL;

 if (getuid() == 0)
 {
 // Sono root
 char *user;
 pw = getpwnam(user = "nobody");
 int newuid = (*pw).pw_uid;
 setuid(newuid);
 }
 else
 setuid(0);
 }*/

/*
 * Thread per l'aggiornamento dei grafici con rrdtool
 * Grafici:
 * - Carico della rete, bit/s
 * - QuantitÔøΩ di pacchetti tcp e udp sulla rete.
 */
void rrdupdate()
{
	//boost::xtime xt; //tempo
	int count = 5;

	//Elimino vecchio file rrd se c'ÔøΩ (dbAll.rrd)
	char filenamedb[200];
	sprintf(filenamedb, "%swww/rrd/dbAll.rrd", absolutePath.c_str());
	//cout << "Path: " << filenamedb << "|" << endl;

	char filenameimm[200];
	sprintf(filenameimm, "%swww/rrd/dbAll.png", absolutePath.c_str());
	//cout << "Path: " << filenameimm << "|" << endl;

	char filenamedb2[200];
	sprintf(filenamedb2, "%swww/rrd/tcpudp.rrd", absolutePath.c_str());
	//cout << "Path: " << filenamedb2 << "|" << endl;

	char filenameimm2[200];
	sprintf(filenameimm2, "%swww/rrd/tcpudp.png", absolutePath.c_str());
	//cout << "Path: " << filenameimm2 << "|" << endl;

	if (remove(filenamedb) == 0) if (verbose) cout << "RRD - Vecchio " << filenamedb << " eliminato" << endl;
	if (remove(filenamedb2) == 0) if (verbose) cout << "RRD - Vecchio " << filenamedb2 << " eliminato" << endl;

	//Creo il database rrd del carico totale di rete in Byte/s
	char dbAll[200];
	sprintf(dbAll, "rrdtool create %s --step=1 DS:byte:COUNTER:2:0:13108000 RRA:AVERAGE:0.5:5:130", filenamedb);
	string out = getStdoutFromCommand(dbAll);
	//cout << "creo test: " << dbAll << endl;
	if (verbose) cout << "M - Creo grafico rrd (dbAll) - " << out << endl;

	//Creo db rrd per numero i pacchetti tcp e udp, da aggiornare ogni secondo
	char tcpudp[200];
	/*sprintf(tcpudp,
	 "rrdtool create %s --step=1 DS:npakUDP:COUNTER:10:0:7000 RRA:AVERAGE:0.5:1:130 DS:npakTCP:COUNTER:10:0:7000 RRA:AVERAGE:0.5:1:130",
	 filenamedb2);*/
	sprintf(tcpudp,
			"rrdtool create %s --step=1 DS:npakUDP:COUNTER:10:0:7000 RRA:AVERAGE:0.5:1:600 DS:npakTCP:COUNTER:10:0:7000 RRA:AVERAGE:0.5:1:600",
			filenamedb2);
	//cout << "creo test2: " << tcpudp << endl;
	out = getStdoutFromCommand(tcpudp);
	if (verbose) cout << "M - Creo grafico rrd (tcpudp) - " << out << endl;

	if (remove(filenameimm) == 0) if (verbose) cout << "RRD - Vecchia " << filenameimm << " eliminata" << endl;
	if (remove(filenameimm2) == 0) if (verbose) cout << "RRD - Vecchia " << filenameimm2 << " eliminata" << endl;

	while (!stop)
	{
		//Aggiorno rrd byte totali
		char cmd[500];
		sprintf(cmd, "rrdtool update %s N:%ld", filenamedb, tot_byte_rete);
		//cout << "test: " << cmd << endl;
		getStdoutFromCommand(cmd);

		//Creo immagine grafico rrd byte totali
		char cmd2[500];
		//char cmd2[500] = "rrdtool graph --start=end-10m --vertical-label Byte dbAll.png DEF:in1=dbAll.rrd:byte:AVERAGE LINE:in1#ff0000:'Byte'";
		sprintf(cmd2, "rrdtool graph --start=end-10m --vertical-label Byte %s DEF:in1=%s:byte:AVERAGE AREA:in1#ff0000:'Byte'", filenameimm,
				filenamedb);
		//cout << "test2: " << cmd2 << endl;
		getStdoutFromCommand(cmd2);
		//if (verbose) cout << "RRD - Creo grafico rrd byte totali";

		if (count >= 5)
		{
			count = 0;
			//Aggiorno rrd pacchetti tcp e udp
			char cmd3[200];
			sprintf(cmd3, "rrdtool update %s --template=npakUDP:npakTCP N:%ld:%ld", filenamedb2, pkt_udp, pkt_tcp);
			//cout << "test3: " << cmd3 << endl;
			getStdoutFromCommand(cmd3);

			//creo grafico rrd pacchetti tcp e udp
			char cmd4[500];
			sprintf(
					cmd4,
					"rrdtool graph --start=end-10m --vertical-label Packets %s DEF:in1=%s:npakTCP:AVERAGE LINE:in1#ff0000:'TCP Packets' DEF:in2=%s:npakUDP:AVERAGE LINE:in2#0000ff:'UDP Packets'",
					filenameimm2, filenamedb2, filenamedb2);
			//cout << "test4: " << cmd4 << endl;
			getStdoutFromCommand(cmd4);
		}
		else
			count++;
		sleep(1);
	}
	if (verbose) cout << "RRD - thread Rrdupdate stoped." << endl;
}

//**************************************************************************************************************************
int main(int argc, char* argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char c;
	uid = geteuid();
	verbose = false; //-v
	porta_webserver = 8080;
	byteSm = 0;
	//inizializzo il vettore degli host
	vHost = vector<host> ();
	struct ether_addr * temp;
	tot_byte_rete = 0;
	puntatoreTrim = NULL;

	if (uid != 0)
	{
		cout << "E - Necessari i privilegi di Root per eseguire Whoml." << endl;
		exit(1);
	}
	if (argc < 1) help();

	while ((c = getopt(argc, argv, "i:wp:v")) != -1)
	{
		switch (c)
		{
		case 'i':
			interface_name = optarg;
			break;
		case 'w':
			webser = true;
			break;
			//case 'p':
			//porta_webserver = atoi(optarg);
			//break;
		case 'v':
			verbose = true;
			break;
		}
	}
	//cartella di esecuzione
	absolutePath = argv[0];
	absolutePath.erase(absolutePath.size() - 5, 5);

	string nulla("");
	if (interface_name == NULL || interface_name == nulla)
	{
		cout << "E - Nessuna interfaccia specificata" << endl;
		cout << endl;
		help();
	}

	//apro l'interfaccia passata come parametro
	in_pcap = pcap_open_live(interface_name, 2096, 1, 500, errbuf);
	//TODO changeUser(); //torno utnte che lancia sudo non nobody, altrimenti non mi scrive file ecc..

	if (in_pcap == NULL)
	{
		fprintf(stderr, "Impossibile aprire il device %s: %s\n", interface_name, errbuf);
		//costruisco l'elenco device di rete disponibili
		if (pcap_findalldevs(&devices_list, errbuf) == -1)
		{
			cout << "M - Errore in pcap_findalldevs " << errbuf << endl;
			exit(1);
		}

		cout << "Interfacce disponibili:" << endl;
		int i = 0;
		for (p = devices_list; p; p = p->next)
		{
			cout << "- " << p->name << endl;
			if (p->description) cout << " (" << p->description << ") " << endl;
			i++;
		}
		if (i == 0)
		{
			cout << "M - Nessuna interfaccia rilevata!" << errbuf << endl;
			exit(1);
		}
		pcap_freealldevs(devices_list); //dealloco la lista dei device

		exit(1);
	}
	else
		cout << "M - Ascolto iniziato" << endl;
	//Apertura interfaccia riuscita

	//customizzo il comportamento di sigaction nel caso riceva un segnale di interruzione
	interruzione.sa_handler = termina;
	terminazione.sa_handler = termina;

	//sa_handler specifica l'azione che sara' associata nel caso in cui venga ricevuto il segnale SIGINT o SIGTERM
	if (sigaction(SIGINT, &interruzione, NULL) > 0) cout << "M - errore nella gestione della terminazione da tastiera" << endl;
	if (sigaction(SIGTERM, &terminazione, NULL) > 0) cout << "M - errore nella gestione della terminazione" << endl;

	//---------- Ricavo i dati dell'interfaccia di rete: -----------
	vector<string> tokensNs;

	bpf_u_int32 mask; /* The netmask of our sniffing device */
	bpf_u_int32 net; /* The IP of our sniffing device */

	if (pcap_lookupnet(interface_name, &net, &mask, errbuf) == -1)
	{
		cout << "M - Errore nel ricavare i dati dell'interfaccia di rete (Interfaccia disconnessa?)" << endl;
		net = 0;
		mask = 0;
		exit(1);
	}
	else
	{
		//ip
		//iplh.s_addr = net; //ip sbagliato sempre .0 finale
		if (pcap_findalldevs(&devices_list, errbuf) == -1)
		{
			cout << "M - Errore nel reperire le informazioni dell'interfaccia " << errbuf << endl;
			exit(1);
		}
		else
		{
			struct sockaddr_in *addr;
			while (devices_list->next)
			{
				if (strcmp(devices_list->name, interface_name) == 0) //interfaccia trovata
				{
					//cout << "TEST interfaccia (" << devices_list->name << ") trovata." << endl;
					// Finche' ci sono indirizzi associati all'interfaccia di rete...
					bool trovato = false;
					vector<string> tokensIp;
					while (devices_list->addresses && !trovato)
					{
						addr = (struct sockaddr_in*) devices_list->addresses->addr;
						//cout << "Indirizzo: " << inet_ntoa(addr->sin_addr) << endl;
						tokenize(inet_ntoa(addr->sin_addr), tokensIp, ".");
						if (tokensIp.at(0).size() >= 2) //il primo numero dell'ip è di almeno 2 cifre
						{
							iplh = addr->sin_addr;
							trovato = true;
						}
						devices_list->addresses = devices_list->addresses->next;
					}
					//prendo l'ultimo ip
					//iplh = addr->sin_addr;
				}
				devices_list = devices_list->next;
			}
		}

		pcap_freealldevs(devices_list); //dealloco la lista dei device

		//netmask
		netmask.s_addr = mask;
		//ricavo il numero di byte della netmask
		if (netmask.s_addr == 16777215) byteSm = 3;
		if (netmask.s_addr == 65535) byteSm = 2;
		if (netmask.s_addr == 255) byteSm = 1;

		//ricavo il Gateway
		char a[200];
		sprintf(a, "arp -na | grep %s", interface_name);
		string netstatOut = getStdoutFromCommand(a);
		tokenize(netstatOut, tokensNs);
		if (tokensNs.size() > 0)
		{
			//Elimino le parentesi tonde prima e dopo l'ip:
			tokensNs.at(1) = (tokensNs.at(1)).erase(0, 1);
			tokensNs.at(1) = (tokensNs.at(1)).erase((tokensNs.at(1)).size() - 1, 1);
			inet_aton((tokensNs.at(1)).c_str(), &gateway);
			tokensNs.clear();
		}
		else
		{
			cout << "M - Errore output ARP nel ricavare l'ip del Gateway." << endl;
			exit(1);
		}

		//Ricavo il Nome
		vector<string> nomelungo;
		if (gethostname(hname, sizeof(hname)) == 0)
		{
			tokenize((string) hname, nomelungo, ".");
			localHostName = nomelungo[0];
		}

		/*ricavo il Gateway
		 char a[200];
		 sprintf(a, "netstat -rn | grep default | grep %s", interface_name);
		 string netstatOut = getStdoutFromCommand(a);
		 tokenize(netstatOut, tokensNs);
		 if (tokensNs.size() > 1)
		 inet_aton((tokensNs.at(1)).c_str(), &gateway);
		 else
		 {
		 cout << "M - Errore output netstat." << endl;
		 exit(1);
		 }
		 if (tokensNs.size() > 0) tokensNs.clear();

		 //Ricavo il Nome
		 vector<string> nomelungo;
		 if (gethostname(hname, sizeof(hname)) == 0)
		 {
		 tokenize((string) hname, nomelungo, ".");
		 localHostName = nomelungo[0];
		 }*/

		//-------------------------------------------------------------------
		//ricavo il Mac del Gateway con: arp -na | grep eth0 | grep 10.0.0.1
		char b[200];
		sprintf(b, "arp -na | grep %s | grep %s", interface_name, inet_ntoa(gateway));
		netstatOut = getStdoutFromCommand(b);
		tokenize(netstatOut, tokensNs);
		if (tokensNs.size() > 1)
		{
			for (u_int i = 0; i < tokensNs.size(); i++)
			{
				if (tokensNs.at(i).size() > 13)
				{
					const char * aaa = tokensNs.at(i).c_str();
					temp = ether_aton(aaa);
				}
			}

			//MAC=
			//gatewaymac = temp->octet;

			//LINUX=
			gatewaymac = temp->ether_addr_octet;
		}
		else
		{
			cout << "M - Errore output ARP nel ricavare il mac del Gateway" << endl;
			exit(1);
		}
		if (tokensNs.size() > 0) tokensNs.clear();

		/*ricavo il Mac del Gateway con: netstat -rn | grep -e "^192.168.100.1 .*en1"
		 char b[200];
		 sprintf(b, "netstat -rn | grep -e \"^%s .*%s\"", inet_ntoa(gateway), interface_name);
		 netstatOut = getStdoutFromCommand(b);
		 tokenize(netstatOut, tokensNs);
		 //gatewaymac = (u_char*) (tokensNs.at(1)).c_str();

		 if (tokensNs.size() > 1)
		 {
		 const char * aaa = tokensNs.at(1).c_str();
		 temp = ether_aton(aaa);
		 //MAC=
		 //gatewaymac = temp->octet;

		 //LINUX=
		 gatewaymac = temp->ether_addr_octet;
		 }
		 else
		 {
		 cout << "M - Errore output netstat" << endl;
		 exit(1);
		 }
		 if (tokensNs.size() > 0) tokensNs.clear();*/

	}

	if (verbose)
	{
		cout << "M - Local Host Name: " << localHostName << endl;
		cout << "M - Local Host Ip: " << inet_ntoa(iplh) << endl;
		cout << "M - Subnet mask = " << inet_ntoa(netmask) << endl;
		cout << "M - Gateway = " << inet_ntoa(gateway);
		cout << " (" << gatewaymac << ")" << endl;
	}

	//Lancio webserver
	int data = 1234567;
	struct mg_context *ctx;
	//boost::xtime xt; //tempo
	if (webser)
	{
		if (verbose) cout << "W - Webserver thread started." << endl;
		// http://code.google.com/p/mongoose/

		ctx = mg_start();
		mg_set_option(ctx, "ports", "8080");
		string wwwpath = absolutePath;
		wwwpath += "www/";
		//cout << "wwwpath: " << wwwpath << "|" << endl;
		mg_set_option(ctx, "root", wwwpath.c_str()); //imposto root
		mg_set_option(ctx, "index_files", "index.html");
		mg_set_uri_callback(ctx, "/vhost", &send_vhost_http, (void *) &data);
		mg_set_uri_callback(ctx, "/json", &send_vhost_json, (void *) &data);
		mg_set_uri_callback(ctx, "/stop", &terminate, (void *) &data);
		if (verbose) cout << "W - Porta webserver: " << porta_webserver << endl;
	}

	//lancio thread
	boost::thread ct(&cattura);
	boost::thread el(&elabora); //TODO valutare se lanciare 1 o + thread in base al carico di lavoro
	boost::thread as(&activescan);
	//boost::thread ws(&webserver);
	boost::thread uf(&updateflux);
	boost::thread rr(&rrdupdate);

	ct.join();
	el.join();
	as.join();
	//ws.join();
	uf.join();
	rr.join();

	if (verbose) cout << " - pulizia -" << endl; //Pulizia
	boost::mutex::scoped_lock lockf(vhost_mutex);
	vHost.clear(); //Pulisco il vettore degli host
	lockf.unlock();
	boost::mutex::scoped_lock lockf1(pkts_mutex);
	pkts.clear(); //Pulisco il buffer circolare dei pacchetti
	lockf1.unlock();
	if (in_pcap) pcap_close(in_pcap); //Libero l'interfaccia di rete
}
