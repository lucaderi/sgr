/*
 * ffProbe.cpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (desensi@cli.di.unipi.it)
 *
 * The main file.
 */

#include "Task.hpp"
#include "Flow.hpp"
#include "Workers.hpp"
#include "stdlib.h"
#include <errno.h>
#include <unistd.h>
#include <pipeline.hpp>

firstStage* first;

/**
 * Prints information on the program.
 * \param progName The name of the program.
 */
void printHelp(char* progName){
fprintf(stderr,"\nusage: %s -i <captureInterface|pcap> [-b <bpf filter>] [-d <idleTimeout>] [-l <lifetimeTimeout>]\n"
		"[-q <queueTimeout>] [-t <readTimeout>] [-w <parDegree>] [-s <hashSize>] [-m <maxActiveFlows>] [-c <cnt>]\n"
		"[-f <outputFile>] [-a <maxAddCheck>] [-z <maxNullCheck>] [-k <maxReadTOCheck>] [-n <host>] [-p <port>] [-y <minFlowSize>]\n"
		"[-r] [-h]\n\n\n", progName);
fprintf(stderr,"-i <captureInterface|pcap> | Interface name from which packets are captured, or .pcap file\n");
fprintf(stderr,"[-b <bpf filter>]          | It specifies a bpf filter.\n");
fprintf(stderr,"[-d <idleTimeout>]         | It specifies the maximum (seconds) flow idle lifetime [default 30]\n");
fprintf(stderr,"[-l <lifetimeTimeout>]     | It specifies the maximum (seconds) flow lifetime [default 120]\n");
fprintf(stderr,"[-q <queueTimeout>]        | It specifies how long (seconds) expired flows (queued before delivery) are emitted [default 30]\n");
fprintf(stderr,"[-t <readTimeout>]         | It specifies the read timeout (milliseconds) when reading from\n"
		"                           | the pcap socket [default 30 seconds]\n");
fprintf(stderr,"[-w <parDegree>]           | It specifies how many thread must be activated [default sequential execution].\n"
		"                           | HashSize %% (parDegree-2) must be equals to 0\n");
fprintf(stderr,"[-s <hashSize>]            | It specifies the size of the hash table where the flows are stored [default 4096]\n"
		"                           | HashSize %% (parDegree-2) must be equals to 0\n");
fprintf(stderr,"[-m <maxActiveFlows>]      | Limit the number of active flows for one worker. This is useful if you want to limit the\n"
		"                           | memory allocated to ffProbe [default 4294967295]\n");
fprintf(stderr,"[-c <cnt>]                 | Cnt is the maximum number of packets to process before returning from reading, but is not a minimum\n"
		"                           | number. When  reading  a  live capture, only one bufferful of packets is read at a time,\n"
		"                           | so fewer than cnt packets may be  processed. If no packets are presents, read returns immediately.\n"
		"                           | A  value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when\n"
		"                           | reading a live capture,  and  causes all the packets in the file to be processed when reading\n"
		"                           | a pcap file [default -1]\n");
fprintf(stderr,"[-f <outputFile>]          | Print the flows in textual format on a file\n");
fprintf(stderr,"[-a <maxAddCheck>]         | Maximum number of flows to check when a worker update a flow in the hash table (-1 is all) [default 1]\n");
fprintf(stderr,"[-z <maxNullCheck>]        | Maximum number of flows to check when a worker receives a NULL flow (-1 is all) [default 1]\n");
fprintf(stderr,"[-k <maxReadTOCheck>]      | Maximum number of flows to check when readTimeout expires (-1 is all) [default -1]\n");
fprintf(stderr,"[-n <host>]                | Host of the collector [default 127.0.0.1]\n");
fprintf(stderr,"[-p <port>]                | Port of the collector [default 2055]\n");
fprintf(stderr,"[-y <minFlowSize>]         | Minimum TCP flow size (in bytes). If a TCP flow is shorter than the specified size the flow\n"
		"                           | is not emitted. 0 is unlimited [default unlimited]\n");
fprintf(stderr,"[-r]                       | Put the interface into 'No promiscous' mode\n");
fprintf(stderr,"[-h]                       | Prints this help\n");
}


int main(int argc, char** argv){
	char *interface=NULL,*collector="127.0.0.1",*bpfFilter=NULL;
	int c,hashSize=4096,cnt=-1,maxAddCheck=1,maxNullCheck=1,maxReadTOCheck=-1,readTimeout=30000;
	uint minFlowSize=0,queueTimeout=30,lifetime=120,parDegree=0,idle=30,maxActiveFlows=4294967295;
	ushort port=2055;
	bool noPromisc=false;
	FILE* output=NULL;
	/**Args parsing.**/
	while ((c = getopt (argc, argv, "i:b:d:l:q:t:w:s:m:c:f:a:z:k:n:p:y:rh")) != -1)
		switch (c){
	        case 'i':
	            interface = optarg;
	            break;
	        case 'b':
	        	bpfFilter = optarg;
	        	break;
	        case 'd':
	        	idle = atoi(optarg);
	        	break;
	        case 'l':
	        	lifetime = atoi(optarg);
	        	break;
	        case 'q':
	        	queueTimeout = atoi(optarg);
	        	break;
	        case 't':
	        	readTimeout = atoi(optarg);
	        	break;
	        case 'w':
	        	parDegree = atoi(optarg);
	        	break;
	        case 's':
	        	hashSize = atoi(optarg);
	        	break;
	        case 'm':
	        	maxActiveFlows = atoi(optarg);
	        	break;
	        case 'c':
	        	cnt=atoi(optarg);
	        	break;
	        case 'f':
	        	output=fopen(optarg,"w");
	        	if(output==NULL)
	        		perror("Opening output file: ");
	        	break;
	        case 'a':
	        	maxAddCheck=atoi(optarg);
	        	break;
	        case 'z':
	        	maxNullCheck=atoi(optarg);
	        	break;
	        case 'k':
	        	maxReadTOCheck=atoi(optarg);
	        	break;
	        case 'n':
	        	collector=optarg;
	        	break;
	        case 'p':
	        	port=atoi(optarg);
	        	break;
	        case 'y':
	        	minFlowSize=atoi(optarg);
	        	break;
	        case 'r':
	        	noPromisc=true;
	        	break;
	        case 'h':
	        	printHelp(argv[0]);
	        	return 1;
	        case '?':
	        	printHelp(argv[0]);
	            return 1;
			default:
				fprintf(stderr,"Unknown option.\n");
	        	exit(-1);
	     }
	if(interface==NULL){
		printf("ERROR: -i <interface> required.\n");
		exit(-1);
	}
	int nWorkers;
	if(parDegree>2){
		assert(hashSize%(parDegree-2)==0);
		nWorkers=parDegree-2;
	}else
		nWorkers=1;
	timeval systemStartTime;
	gettimeofday(&systemStartTime,NULL);
	uint32_t sst=systemStartTime.tv_sec*1000+systemStartTime.tv_usec/1000;
	/**
	 * Initializes the fastflow's memory allocator.
	 */
	ff::ff_allocator ffalloc;
	if (ffalloc.init()<0){
		fprintf(stderr,"Initialization of fastflow's memory allocator fail.");
		return -1;
	}
	/**Creates the first stage of the pipeline (reader).**/
	first=new firstStage(nWorkers,interface,noPromisc,bpfFilter,cnt,hashSize,readTimeout,&ffalloc);
	/**Creates the last stage of the pipeline (exported).**/
	lastStage *last=new lastStage(output,queueTimeout,collector,port,minFlowSize,sst);



	if(parDegree<=1){
		/**Sequential execution**/
		genericStage worker(0,hashSize,maxActiveFlows,idle,lifetime,maxNullCheck,maxAddCheck,maxReadTOCheck);
		while(last->svc(worker.svc(first->svc(NULL)))==GO_ON);
	}else if(parDegree==2){
		/**Parallel execution with two pipelined threads.**/
		genericStage worker(0,hashSize,maxActiveFlows,idle,lifetime,maxNullCheck,maxAddCheck,maxReadTOCheck);
		workerAndExporter wae(&worker,last);
		ff::ff_pipeline pipe;
		pipe.add_stage(first);
		pipe.add_stage(&wae);
		pipe.run_and_wait_end();
		pipe.ffStats(std::cout);
	}else{
		/**Parallel execution with n pipelined threads.**/
		ff::ff_pipeline pipe;
		genericStage** stages=new genericStage*[nWorkers];
		int workerHs=hashSize/nWorkers;
		/**Add the stages of the pipeline (they are linked in the order in which they are added).**/
		pipe.add_stage(first);
		for(int i=0; i<nWorkers; i++){
			stages[i]=new genericStage(i,workerHs,maxActiveFlows,idle,lifetime,maxNullCheck,maxAddCheck);
			pipe.add_stage(stages[i]);
		}
		pipe.add_stage(last);
		/**Starts the computation and waits for the end.**/
		pipe.run_and_wait_end();
		pipe.ffStats(std::cout);
		for(int i=0; i<nWorkers; i++)
			delete stages[i];
		delete[] stages;
	}
	if(output!=NULL) fclose(output);
	delete first;
	delete last;
	return 0;
}
