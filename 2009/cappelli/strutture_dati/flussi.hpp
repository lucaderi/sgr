/*
 * flussi.hpp
 * Fornisce la struttura dati e i metodi per gestire un database dei flussi di rete
 */

#ifndef FLUSSI_HPP_
#define FLUSSI_HPP_

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <vector>
#include <boost/thread/xtime.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition.hpp>
#include "../protocolswitch.hpp"

using namespace std;
const int nFlussi = 1000;
const int maxSleepFlux = 5; //in minuti

class flussi
{
private:
	struct flusso
	{
		struct in_addr ipM;
		struct in_addr ipD;
		unsigned int portaM;
		unsigned int portaD;
		unsigned long int nPacchetti;
		bool protocol; //true = TCP, false = UDP;
		unsigned int lastUpdate; //In secondi
		bool terminato;
		flusso() :
			portaM(0), portaD(0), nPacchetti(0), lastUpdate(0), terminato(false)
		{
		}
	};
	flusso *arrayFlussi;
	vector<unsigned int> portsTcp;
	vector<unsigned int> portsUdp;
	vector<int> indiciAttivi; //Posizioni attive al'interno dell'array dei flussi, usato per ottimizzare le scansioni.
	int hash(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol);
	boost::xtime xt; //tempo
	boost::mutex f_mutex; //Mutex sui flussi

public:
	flussi();
	~flussi();
	void addFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol);//pacchetto di SYN arrivato, creo
	void incrementFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol); //se tcp: ret false se flusso non esiste, se UDP aggiunge il flusso
	bool deleteFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol); //pacchetto di FIN arrivato, elimino
	bool getTerminato(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol);
	void setTerminato(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol);
	//Restituisce le porte TCP significative (controlla ipmittente - porta destinatario) dell'host passato come parametro
	void hostPortsTcp(struct in_addr ip, vector<unsigned int>* portsTcp);
	//Restituisce le porte UDP significative (controlla ipmittente - porta destinatario) dell'host passato come parametro
	void hostPortsUdp(struct in_addr ip, vector<unsigned int>* portsUdp);
	void clearOldFlux();
	void print();
};
#endif /* FLUSSI_HPP_ */
