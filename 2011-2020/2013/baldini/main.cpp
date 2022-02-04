
#include <iostream>
#include <ff/mapping_utils.hpp>
#include <ff/mapper.hpp>
#include <ff/buffer.hpp>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "packet.hpp"
#include "blacklist.hpp"
#include "netdevice.hpp"
#include "emitter.hpp"
#include "worker.hpp"
#include "collector.hpp"


/* controlla diverso da 0; stampa errore e termina */
#define ec_div0(s,m) if(s) {perror(m); exit(errno);}
/* stampa a video tramite sys call
#define SysWrite(s) write(1,s,strlen(s)); */

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/*
 * variabili globali
 */
int nEmitters;
int nWorkers;
int nCollectors;
int nCores;
ff::SWSR_Ptr_Buffer** worker_in_ch;
ff::SWSR_Ptr_Buffer** collector_in_ch;
host_list bl;

using namespace std;

int main(int argc,char** argv){

	ff::threadMapper* utils = ff::threadMapper::instance();
	if(argc < 5){
		cout << "Numero argomenti sbagliato" <<endl;
		exit(EXIT_FAILURE);
	}
	nEmitters = atoi(argv[1]);
	if(nEmitters < 1){
		cout << "Il numero di emettitori maggiore di zero" <<endl;
		exit(EXIT_FAILURE);
	}
	nWorkers = atoi(argv[2]);
	const int bufSize = atoi(argv[3]);
	char* blackListName = argv[4];
	nCollectors = nEmitters;
	if(argc != 5 + nEmitters){
		cout << "Non hai specificato il nome delle devices" <<endl;
		exit(EXIT_FAILURE);
	}
	char* devNames[nEmitters];
	for(int i = 5,j=0; i < 5+nEmitters ;i++,j++){
		devNames[j] = argv[i];
	}

	if(! bl.load(blackListName) ){
		 cout<<"File:\'"<< blackListName <<"\' NON esiste"<<endl;
		 exit(EXIT_FAILURE);
	}

	pthread_t emitterIDs[nEmitters];
	void*  emitterStatus[nEmitters];

	pthread_t workerIDs[nWorkers];
	void*  workerStatus[nWorkers];

	pthread_t collectorIDs[nCollectors];
	void*  collectorStatus[nCollectors];

	worker_in_ch = new ff::SWSR_Ptr_Buffer*[nWorkers];
	collector_in_ch = new ff::SWSR_Ptr_Buffer*[nCollectors];



	for(int i = 0;i<nCollectors;i++){
		collector_in_ch[i] = new ff::SWSR_Ptr_Buffer(bufSize);
		collector_in_ch[i]->init();
		collector_par_t* par = new collector_par_t(devNames[i],utils->getCoreId(),collector_in_ch[i]);
		ec_div0(pthread_create(&collectorIDs[i],NULL,collector,par),"Errore: creazione collector");
	}


	for(int i = 0;i<nWorkers;i++){
		worker_in_ch[i] = new ff::SWSR_Ptr_Buffer(bufSize);
		worker_in_ch[i]->init();
		worker_par_t* par = new worker_par_t(utils->getCoreId(),worker_in_ch[i]);
		ec_div0(pthread_create(&workerIDs[i],NULL,worker,par),"Errore: creazione worker");
	}

	for(int i = 0;i<nEmitters;i++){
		emitter_par_t* par;
		if(i%2 == 0)
			par = new emitter_par_t(devNames[i],i,utils->getCoreId(),i+1);
		else
			par = new emitter_par_t(devNames[i],i,utils->getCoreId(),i-1);

		ec_div0(pthread_create(&emitterIDs[i],NULL,emitter,par),"Errore: creazione emitter");
	}



	/** mi sincronizzo con le terminazioni dei thread*/
	for(int i = 0;i<nEmitters;i++)
		pthread_join(emitterIDs[i],&emitterStatus[i]);
	for(int i = 0;i<nWorkers;i++)
		pthread_join(workerIDs[i],&workerStatus[i]);
	for(int i = 0;i<nCollectors;i++)
		pthread_join(collectorIDs[i],&collectorStatus[i]);

	exit(EXIT_SUCCESS);
}

