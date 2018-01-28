/*
 * Workers.hpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (desensi@cli.di.unipi.it)
 *
 * This file contains the definitions of the fastflow's workers.
 */

#ifndef WORKERS_HPP
#define WORKER_HPP
#include <pcap.h>
#include <node.hpp>
#include <queue>
#include <signal.h>
#include <allocator.hpp>
#include "HashTable.hpp"

uint hsize, ///<Size of the hash table
	datalinkOffset, ///<Length of the datalink header
	nWorkers; ///< Number of workers
bool quit; ///< Flag for the termination of the probe
ff::ff_allocator *ffalloc; ///< Fastflow's allocator
pcap_t *handle; ///< Pcap handle

/**
 * The function called by pcap_dispatch when a packet arrive.
 * \param user A param passed by the worker.
 * \param phdr The header of the packet.
 * \param pdata The packet.
 */
inline void dispatchCallback(u_char *user, const struct pcap_pkthdr *phdr, const u_char *pdata){
	Task* t=(Task*) user;
	hashElement* f=getFlow(pdata,datalinkOffset,ffalloc);
	if(f==NULL) return;
	f->dOctets=phdr->len-datalinkOffset;
	f->First=phdr->ts;
	int hashValue=hashFun(f,hsize);
	int workerId=hashValue/(hsize/nWorkers);
	f->hashId=hashValue%(hsize/nWorkers);
	t->setFlowToAdd(f,workerId);
}

/**
 * Signal handler for SIGINT.
 */
inline void handler(int i){
	printf("SIGINT Received. The probe will end at the arrive of a packet or at the expiration of readTimeout.\n");
	quit=true;
	pcap_breakloop(handle);
}

/**
 * First stage of the pipeline (captures the packets).
 */
class firstStage:public ff::ff_node{
private:
	int cnt, ///< Maximum number of packet to read from the device (or from the .pcap file)
		pktRcvd; ///< Packet received after a call of 'pcap_dispatch'
	bool offline, ///< True if the device is a .pcap file
		end; ///< Flag for the termination of the pipeline
public:
	/**
	 * Constructor of the first stage.
	 * \param nw Number of workers.
	 * \param device Name of the device (or of the .pcap file)
	 * \param noPromisc False if the interface must be set in promiscous mode, false otherwise.
	 * \param filter_exp A bpf filter.
	 * \param cnt Maximum number of packet to read from the device (or from the .pcap file)
	 * \param h Size of the hash table (Sizeof(HashOfWorker1)+Sizeof(HashOfWorker2)+...+Sizeof(HashOfWorkerN))
	 * \param readTimeout The read timeout when reading from the pcap socket
	 * \param alloc A pointer to the fastflow's allocator
	 */
	inline firstStage(int nw, const char* device, bool noPromisc, char* filter_exp, int cnt, int h, int readTimeout, ff::ff_allocator *alloc):
	cnt(cnt),pktRcvd(0),end(false){
		ffalloc=alloc;
		nWorkers=nw!=0?nw:1;
		quit=false;
		hsize=h;
		char errbuf[PCAP_ERRBUF_SIZE];
		struct bpf_program fp;		/* The compiled filter expression */
		/**Accepts only ipv4 traffic.**/
		bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 	bpf_u_int32 net;		/* The IP of our sniffing device */
	 	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
	 		handle=pcap_open_offline(device,errbuf);
	 		offline=true;
	 		net = 0;
	 		mask = 0;
	 	}else{
	 		int prom=noPromisc?0:1;
	 		handle = pcap_open_live(device, 200, prom, readTimeout, errbuf);
	 		offline=false;
	 	}
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
			exit(-1);
		}
		/**Accepts only ipv4 traffic (netflow v5 doesn't support other network protocols).**/
		if (pcap_compile(handle, &fp, "ip", 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(-1);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(-1);
		}
		pcap_freecode(&fp);
		/**Sets the filter passed by user.**/
		if(filter_exp!=NULL){
			if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				exit(-1);
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				exit(-1);
			}
			pcap_freecode(&fp);
		}
		int datalinkType=pcap_datalink(handle);
		//TODO Add other switch-case to add the support to other datalink's protocols.
		switch(datalinkType){
			case 1:
				datalinkOffset=14;
				break;
			default:
				fprintf(stderr, "Datalink offset for datalink type: %d unknown.",datalinkType);
				exit(-1);
		}
		/**
		 * Signal handling.
		 */
		struct sigaction s;
		bzero( &s, sizeof(s) );
		s.sa_handler=handler;
		sigaction(SIGINT,&s,NULL);
		/**
		 * Registers this thread as allocator
		 */
		if (ffalloc->registerAllocator()<0){
			fprintf(stderr,"ffalloc->registerAllocator() fail.");
			exit(-1);
		}
	}

	/**
	 * Destructor of the first stage.
	 */
	inline ~firstStage(){
		pcap_close(handle);
	}


	/**
	 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
	 */
	inline void* svc(void*){
		if(end){
			ffalloc->deregisterAllocator();
			return NULL;
		}else{
			Task* t=(Task*) ffalloc->malloc(sizeof(Task));
			t->init(nWorkers,ffalloc);
			pktRcvd=pcap_dispatch(handle,cnt,dispatchCallback,(u_char*)t);
			if((pktRcvd==0 && offline) || quit){
				end=true;
				t->setEof();
			}
			else if(pktRcvd==0 && !offline){
				t->setReadTimeoutExpired();
			}
			return t;
		}
	}
};

/**
 * This worker adds the flows to the hash table.
 */
class genericStage:public ff::ff_node{
private:
	int id,hs,idle,lifeTime,maxfNull,maxfRange,maxfAdd,maxReadTOCheck;
	Hash* h;
public:
	/**
	 * Constructor of a generic stage of pipeline.
	 * \param id The id of this worker.
	 * \param hSize The size of this part of hash table.
	 * \param maxActiveFlows Max number of active flows.
	 * \param idle Max number of seconds of inactivity (max 24h). (Default is 30).
	 * \param lifeTime Max number of life's seconds of a flow (max 24h). (Default is 120).
	 * \param maxfNull Max number of flows to check when a worker receives a NULL flow (-1 is all), default is 1.
	 * \param maxfAdd Max number of flows to check when a worker adds a flow to the hash table (-1 is all), default is 1.
	 * \param maxReadTOCheck Max number of flows to check when readTimeout expires (-1 is all), default is -1.
 	 */
	inline genericStage(int id, int hSize, int maxActiveFlows, int idle=30, int lifeTime=120, int maxfNull=1, int maxfAdd=1, int maxReadTOCheck=-1):
	id(id),hs(hSize),idle(idle),lifeTime(lifeTime),maxfNull(maxfNull),maxfRange(maxfRange),maxfAdd(maxfAdd),maxReadTOCheck(maxReadTOCheck){
		h=new Hash(hs,maxActiveFlows,ffalloc);
		struct sigaction s;
		bzero( &s, sizeof(s) );
		s.sa_handler=handler;
		sigaction(SIGINT,&s,NULL);
	}

	/**
	 * Destructor of the stage.
	 */
	inline ~genericStage(){
		delete h;
	}

	/**
	 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
	 */
	void* svc(void* p){
		Task* t=(Task*) p;
		if(t==NULL)
			return NULL;
		myList<hashElement*> *flowsToExport=t->getFlowsToExport();
		time_t now;
		myList<hashElement*> *flowsToAdd=t->getFlowsToAdd(id);
		int ftaSize=flowsToAdd->size();
		/**If the read timeout is expired.**/
		if(t->isReadTimeoutExpired()){
			now=time(NULL);
			h->checkExpiration(maxReadTOCheck,idle,lifeTime,flowsToExport,&now);
		}
		/**If there isn't flows to add.**/
		else if(ftaSize==0){
			now=time(NULL);
			if(t->isEof())
				/**If end of file is arrived checks all the hash table and considers all flows expired.**/
				h->checkExpiration(-1,idle,lifeTime,flowsToExport,NULL);
			else
				h->checkExpiration(maxfNull,idle,lifeTime,flowsToExport,&now);
		}else{
			now=h->updateFlows(flowsToAdd,flowsToExport);
			if(t->isEof())
			/**If end of file is arrived checks all the hash table and considers all flows expired.**/
				h->checkExpiration(-1,idle,lifeTime,flowsToExport,NULL);
			else
				h->checkExpiration(maxfAdd*ftaSize,idle,lifeTime,flowsToExport,&now);
		}
		return t;
	}
};

/**
 * The last stage of the pipeline (exports the expired flows).
 */
class lastStage:public ff::ff_node{
private:
	FILE* out; ///<File where to print the flows in textual format.
	uint qTimeout, ///<It specifies how long expired flows (queued before delivery) are emitted
		flowSequence, ///<Sequence number for the flows to export
		minFlowSize;///<Minimum tcp flows size
	std::queue<hashElement*>* q; ///< Queue of expired flows
	time_t lastEmission; ///< Time of the last export
	Exporter ex;
	/**
	 * Exports the flow to the remote collector (also prints it into the file).
	 */
	inline void exportFlows(){
		int size=q->size();
		ex.sendToCollector(q,flowSequence,out);
		flowSequence+=size;
	}
public:
	/**
	 * Constructor of the last stage of the pipeline.
	 * \param out The FILE* where to print exported flows.
	 * \param queueTimeout It specifies how long expired flows (queued before delivery) are emitted.
	 * \param collector The host of the collector.
	 * \param port The port where to send the flows.
	 * \param minFlowSize If a TCP flow doesn't have more than minFlowSize bytes isn't exported (0 is unlimited).
	 * \param systemStartTime The system start time.
	 */
	inline lastStage(FILE* out,uint queueTimeout,char* collector, uint port, uint minFlowSize, uint32_t systemStartTime):out(out),qTimeout(queueTimeout),flowSequence(0),
	minFlowSize(minFlowSize),q(new std::queue<hashElement*>),lastEmission(time(NULL)),ex(collector,port,ffalloc,systemStartTime){
		if(out!=NULL)
			fprintf(out,"IPV4_SRC_ADDR|IPV4_DST_ADDR|OUT_PKTS|OUT_BYTES|FIRST_SWITCHED|LAST_SWITCHED|L4_SRC_PORT|L4_DST_PORT|TCP_FLAGS|"
					"PROTOCOL|SRC_TOS|\n");
		struct sigaction s;
		bzero( &s, sizeof(s) );
		s.sa_handler=handler;
		sigaction(SIGINT,&s,NULL);
		assert(ffalloc!=NULL);
		if (ffalloc->register4free()<0) {
			fprintf(stderr,"lastStage, register4free fails\n");
		    exit(-1);
		}
	}

	/**
	 * Destructor of the stage.
	 */
	inline ~lastStage(){
		delete q;
	}

	/**
	 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
	 */
	void* svc(void* p){
		Task* t=(Task*) p;
		hashElement* f;
		if(p!=NULL){
			myList<hashElement*>* l=t->getFlowsToExport();
			assert(t->elementsToAddSize() == 0);
			time_t now=time(NULL);
			while(l->size()!=0){
				assert(l->pop(&f)==0);
				if(!(f->prot==TCP_PROT_NUM && f->dOctets<minFlowSize))
					q->push(f);
				if(q->size()==30){
					exportFlows();
					lastEmission=now;
				}
			}
			/**Exports flows every qTimeout seconds.**/
			if((t->isEof() || (now-lastEmission>=qTimeout)) && !q->empty()){
				exportFlows();
				lastEmission=now;
			}
			t->~Task();
			ffalloc->free(t);
			return GO_ON;
		}else{
			if(!q->empty())
				exportFlows();
			return NULL;
		}
	}
};

/**
 * A stage that adds the flows to the hash table and exports the expired flows.
 */
class workerAndExporter: public ff::ff_node{
private:
	genericStage* worker;
	lastStage* exporter;
public:
	/**
	 * Constructor of the stage.
	 * \param w The stage that adds the flows to the hash table.
	 * \param e The stage that exports the expired flows.
	 */
	inline workerAndExporter(genericStage* w, lastStage* e):worker(w),exporter(e){;}

	/**
	 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
	 */
	inline void* svc(void* t){
		return exporter->svc(worker->svc(t));
	}
};

/**
 * A stage that captures the packets and adds it to the hash table.
 */
class snifferAndWorker: public ff::ff_node{
private:
	firstStage* sniffer;
	genericStage* worker;
public:
	/**
	 * Constructor of the stage.
	 * \param s The stage that captures the packets.
	 * \param w The stage that adds the flows to the hash table.
	 */
	inline snifferAndWorker(firstStage* s,genericStage* w):sniffer(s),worker(w){;}

	/**
	 * The function computed by one stage of the pipeline (is computed by an indipendent thread).
	 */
	inline void* svc(void* t){
		return worker->svc(sniffer->svc(t));
	}
};

#endif /**WORKERS_HPP**/
