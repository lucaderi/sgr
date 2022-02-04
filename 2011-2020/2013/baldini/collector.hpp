#ifndef c_hpp
#define c_hpp

#include "packet.hpp"
#include "netdevice.hpp"
using namespace std;
/**
 * struct necessaria per il passaggio di paramentri
 * alle funzioni dei thread
 */
 struct collector_par{
	 collector_par(char* devName,int coreid,ff::SWSR_Ptr_Buffer* b){
		 this->devName = devName;
		 this->coreID = coreid;
		 this->buf = b;
	 }
	 char* devName;
	 int coreID;
	 ff::SWSR_Ptr_Buffer* buf;
 };
typedef struct collector_par collector_par_t;

/**
 * Task del collettore
 */
static void* collector(void* arg){
	collector_par_t* par = (collector_par_t*)arg;
	ff::SWSR_Ptr_Buffer* in_buf = par->buf;
	ff_mapThreadToCpu(par->coreID); //pinning
	net_device dev;
	void* data;

	if( ! dev.openLive(par->devName) ){
		cout << "Collector: Errore apertura dev - "<< dev.errbuf << endl;
		exit(EXIT_FAILURE);
	}
	while(true)
	{
		if(in_buf->pop(&data))
		{
			if(! isEOS(data) ){ //se non è fine stream
				if( ! dev.write((packet*)data) )cout << "Collector: error while sending packet on " << par->devName << endl;
				delete ((packet*)data);
			}
			else
			{
				//cout << "collector terminato"<<endl;
				pthread_exit(0);
			}

		}
		else
		{
			usleep(1);
		}


	}
	pthread_exit(0);
}

#endif
