#ifndef w_hpp
#define w_hpp

#include <iostream>
#include <fstream>
#include <pthread.h>
#include <ff/mapping_utils.hpp>
#include <ff/ubuffer.hpp>
#include <ff/mapper.hpp>
#include <vector>
#include <list>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <unordered_map>
#include "dataflows.hpp"
#include "packet.hpp"
#include "blacklist.hpp"

using namespace std;
/**
* Valore che identifica il numero di secondi necessari affichè un flusso sia dichiarato inattivo
*/
#define INACTIVE_FLOW 120
/**
 * Struttura che mantiene le informazioni necessarie per
 * il passaggio di paramentri alla funzione task del thread worker.
 */
 struct worker_par{
	 worker_par(int core,ff::SWSR_Ptr_Buffer* b){
		 coreID = core;
		 buf = b;
	 }
	 int coreID;
	 ff::SWSR_Ptr_Buffer* buf;
 };
typedef struct worker_par worker_par_t;
/**
 * Canali di comunicazione di output dei worker.
 */
extern ff::SWSR_Ptr_Buffer** collector_in_ch;
/**
 * Black list.
 */
extern host_list bl;
/**
 * Funzione per inviare i dati sullo stream di output del worker
 */
inline void ch_send_out(packet* pkt){
	collector_in_ch[pkt->getOutDevID()]->mp_push(pkt);
}
/**
 * Handler per la gestione fin e ack successivi ai fin relativi ai pacchetti.
 * I flussi con connessione terminata vengono messi infondo alla lista relativa
 * all'implementazione della politica move to front.
 */
inline void tcp_termination_handler(packet* pkt,state* status, pair<flow*,state*>* p,list< pair<flow*,state*> >* mtf){
	if( pkt->hasTcpFinFlag() )status->setFinFlag();
	if( pkt->hasTcpAckFlag() )status->setAckOfFinFlag();
	if(status->isClosed()){
		mtf->remove(*p);
		mtf->push_back(*p);
	}
}
/**
 * Handler per la gestione dei pacchetti HTTP letti da rete.
 */
inline void pkt_handler(data_flows& df,list< pair<flow*,state*> >& mtf,void* data){
	char buf[BUFSIZ];
	packet* pkt = (packet*)data;
	time_t now = pkt->getTime()->tv_sec;
	flow flow_key( pkt->getSourceIP(),pkt->getDestinationIP(),pkt->getSourcePort(),pkt->getDestinationPort(),pkt->getTos() );
	state* status;
	pair<flow*,state*> pair; //CONTROLLO SE NELLA MAPPA ESISTE GIA' UN RECORD PER QUESTO FLUSSO
	if( ! df.getState(flow_key,&pair) ){ //chiave di flusso e stato, scritti nella coppia pair
		//pair non è significativa in questo ramo
		status = NULL;
	}
	else {
		status = pair.second;
		mtf.remove(pair);
		mtf.push_front(pair);
	}
	if( ! status ) //FLUSSO NON ESISTE ANCORA NELLA STRUTTURA
	{
		ch_send_out(pkt);//invio dati al collector
		state s(state::UNKNOWN,now);
		df.add_new_flow(flow_key,s);
		return;
	}
	else if( status->isAllowed() ) //FLUSSO CONCORDATO
	{
		ch_send_out(pkt);//invio dati al collector
		status->updateTime(now); //flusso ancora attivo
		tcp_termination_handler(pkt,status,&pair,&mtf);
	}
	else if( status->isUnknown() ) //FLUSSO ANCORA NON RICONOSCIUTO
	{
		char* payload = pkt->getHttpHost(buf,BUFSIZ);
		if( payload ){
			bool isIn = bl.query(payload);
			cout << "Worker=>" << "Host: " << payload << " is in the black list? = " << isIn << endl;
			if(!isIn)
			{
				ch_send_out(pkt);//invio dati al collector
				status->setState(state::ALLOWED);
			}
			else //not allowed flow
			{
				status->setState(state::BLOCKED);
			}
		}
		else ch_send_out(pkt);// non c'è payload invio dati al collector
		status->updateTime(now); //flusso ancora attivo
		tcp_termination_handler(pkt,status,&pair,&mtf);
	}
	else if( status->isBlocked() )//FLUSSO NON PERMESSO
	{
		//se flusso di controllo arriva qua => pkt è da droppare
		status->updateTime(now); //flusso ancora attivo
		tcp_termination_handler(pkt,status,&pair,&mtf);
	}

	//elimino i flussi non più attivi o chiusi
	while(
			!mtf.empty() &&
			(
			mtf.back().second->isInactive(now,INACTIVE_FLOW) ||
			mtf.back().second->isClosed()
			)
	)
	{
		if(mtf.back().second->isClosed()){cout << "Connessione terminata : " << mtf.back().first << endl;}
		if(mtf.back().second->isInactive(now,INACTIVE_FLOW)){cout << "Flusso Inattivo :  "<< mtf.back().first << endl;}
		df.remove(*mtf.back().first);
		mtf.pop_back();
	}



}

/**
* Valore che identifica il numero di secondi con cui ripulire la struttura dei flussi

#define FREQ_ANALYSIS 5
/**
 * Task per analizzare la struttura data flows, L'analisi consiste appunto nel controllare tutti i record  e
 * verificare se vi sono dei flussi terminati, una volta trovati questi vengono eliminati.

inline void dataflow_cleaner(data_flows& df,time_t now,size_t& bckPos){
	unordered_map<flow,state>* m = df.getMap();
	if(m->size() == 0)return;
	vector<const flow*> vett;
	//calcola i flussi da eliminare e li aggiunge ad una struttura temporanea
	//non si può cancellare gli elementi mentre si itera sulla struttura
	for ( auto it = m->begin(bckPos); it != m->end(bckPos); ++it ){
		if( it->second.isClosed() )
			{cout << "Connessione terminata : " << it->first << endl; vett.push_back(&(it->first));}
		else if( it->second.isInactive(now,INACTIVE_FLOW) )
			{cout << "Flusso Inattivo :  "<< it->first << endl; vett.push_back(&(it->first));}
		it->second.updateTime(false);
	}
	bckPos = (bckPos + 1) % m->bucket_count(); // aggiorno puntatore per la prossima iterazione
	//Leggo la lista degli puntatori da eliminare dalla struttura data flows
	for( int i=0;i<vett.size();i++)
		df.remove(*vett.at(i));
}
 */

/**
 * Task del worker
 */
static void* worker(void* arg){
	data_flows df;
	list< pair<flow*,state*> > mtf;
	worker_par_t* p = (worker_par_t*)arg;
	ff::SWSR_Ptr_Buffer* in_buf = p->buf;
	ff_mapThreadToCpu(p->coreID); //pinning
	//cout << "worker mappato su "<< p->coreID <<endl;
	void* data;
	while(true)
	{
		if(in_buf->pop(&data))
		{
			if( ! isEOS(data) )
			{
				packet* pkt = (packet*)data;
				if( pkt->isHTTP() )pkt_handler(df,mtf,data); //gestore per HTTP pkt
				else ch_send_out(pkt); //se il pkt non è HTTP => può passare
			}
			else
			{
				close_channels(collector_in_ch,nCollectors);
				pthread_exit(0);
			}
		}
		else
		{
			usleep(1);
			/**
			 * 1 pacchetto ongi 67 nanosecondi
			 * 1000/67 = 14 pacchetti
			 */
		}
	}
	pthread_exit(0);
}


#endif

