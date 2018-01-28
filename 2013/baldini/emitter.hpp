#ifndef e_hpp
#define e_hpp

#include <pthread.h>
#include "packet.hpp"

using namespace std;

extern int nEmitters;
extern int nWorkers;
extern int nCollectors;
extern int nCores;
extern ff::SWSR_Ptr_Buffer** worker_in_ch;
extern ff::SWSR_Ptr_Buffer** collector_in_ch;
extern host_list bl;

inline bool isEOS(void* data){
	return(data == EOS);
}
inline void close_channels(ff::SWSR_Ptr_Buffer** bufs,const int n){
	for(int i=0;i<n;i++)
		bufs[i]->mp_push(EOS);
}

struct emitter_par{
	emitter_par(char* devName,int mydevID,int coreID,int outDev){
		this->devName = devName;
		this->mydevID = mydevID;
		this->coreID = coreID;
		this->outDev = outDev;
	}
	char* devName; //nome periferica da aprire in sola lettura
	int mydevID; //id periferica da aprire in lettura
	int coreID; //id core su cui eseguire il task emitter
	int outDev; //id periferica su cui andare a scrivere i dati letti

};
typedef struct emitter_par emitter_par_t;

/**
 * Task dell'emettitore
*/
static void* emitter(void* arg){
	emitter_par_t* par = (emitter_par_t*) arg;
	ff_mapThreadToCpu(par->coreID); //pinning
	//cout << "emitter mappato su "<< par->coreID <<endl;
	cout << "Emitter mappato su "<< par->devName << " ID:"<< par->mydevID<< ", invia a "<<par->outDev <<endl;
	net_device dev;
	if( ! dev.openLive(par->devName) ){
		cout << "Emitter: " << par->devName << ", Error while opening dev - "<< dev.errbuf << endl;
		exit(EXIT_FAILURE);
	}
	if( ! dev.setReadOnlyMode() ){
		cout << "Emitter: " << par->devName << ", Error while setting read-only mode on dev - "<< dev.errbuf << endl;
		exit(EXIT_FAILURE);
	}
	int rxcode;
	while(true)
	{
		rxcode = dev.readPkt();
		if(rxcode == 1) // Lettura pacchetto con successo
		{
			u_char* buf = new u_char[dev.getPcapHeader()->caplen];
			memcpy(buf,dev.getPktData(),dev.getPcapHeader()->caplen); //Crea una copia indipendente del pacchetto !!!
			packet* pkt = new packet(buf,dev.getPcapHeader(),par->outDev);
			unsigned int hashcode = pkt->hash(nWorkers);
			worker_in_ch[hashcode]->mp_push(pkt);
		}
		else if (rxcode == -2) // Si sta leggendo da File pcap, ed e' finito il file
		{
			cout << "Emitter: Fine Lettura dati da file Pcap " << endl;
			close_channels(worker_in_ch,nWorkers);
			pthread_exit(0);
		}

	}
	close_channels(worker_in_ch,nWorkers);
	pthread_exit(0);
}


#endif



