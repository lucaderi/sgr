#include "globals.h"

using namespace std;

static int i;

void createRecvPktArray(){
	if(verbose_mode)
		printf("Creating recv pkt array ... ");

  recv_pkt_array = (recv_pkt_t *)calloc(recv_pkt_array_size, sizeof(recv_pkt_t));
  if(recv_pkt_array == NULL){
		printf("Can't create recv pkt array ! Quitting ...\n");
    exit(EXIT_FAILURE);
	}
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createFlowHTArray(){ 
  if(verbose_mode)
    printf("Creating flow hash table array ... ");

  hash_table_array = new (nothrow) flowHashTable * [thread_number];
  if(hash_table_array == NULL){
    printf("Can't create flow hash table array ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  for(i=0; i<thread_number; i++){
    hash_table_array[i] = new (nothrow) flowHashTable(hash_table_size);
    if(hash_table_array[i] == NULL){
      printf("Can't create a flow hash table ! Quitting ...\n");
      exit(EXIT_FAILURE);
    }
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createIPQDetStructArray(){
	static IPOQUE_PROTOCOL_BITMASK ipq_proto_bitmask;
  IPOQUE_BITMASK_SET_ALL(ipq_proto_bitmask);

  if(verbose_mode)
    printf("Creating ipoque detection struct array ... ");

  ipoque_struct_array = new (nothrow) ipoque_detection_module_struct * [thread_number];
  if(ipoque_struct_array == NULL){
    printf("Can't create ipoque detection struct array ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  for(i=0; i<thread_number; i++){
    ipoque_struct_array[i] = ipoque_init_detection_module(DEFAULT_TICK_RESOLUTION, calloc_wrapper, NULL);
    if(ipoque_struct_array[i] == NULL){
      printf("Can't create a ipoque detection struct ! Quitting ...\n");
      exit(EXIT_FAILURE);
    }
    ipoque_set_protocol_detection_bitmask2(ipoque_struct_array[i], &ipq_proto_bitmask);
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createLocalTIDArray(){
  if(verbose_mode)
		printf("Creating local thread id array ... ");
    
  local_tid_array = new (nothrow) int [thread_number];
  if(local_tid_array == NULL){
		printf("Can't create local thread id array ! Quitting ...\n");
    exit(EXIT_FAILURE);
	}
	for (i=0; i<thread_number; i++){
    local_tid_array[i] = i;
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createMonitorThreads(){  
  if(verbose_mode)
    printf("Creating monitor threads ... ");

  pthread_array = new (nothrow) pthread_t [thread_number];
  if(pthread_array == NULL){
    printf("Can't create monitor thread array ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  for(i=0; i<thread_number; i++){
    if(pthread_create(&pthread_array[i], NULL, monitorThread, (void *)&local_tid_array[i]) != 0){
      printf("Can't create a monitor thread ! Quitting ...\n");
      exit(EXIT_FAILURE);
    }
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createSignalHandlerThread(){
	if(verbose_mode)
    printf("Creating signal handler thread ... ");

  if(pthread_create(&signalHandlerTID, NULL, signalHandlerThread, NULL) != 0){
    printf("Can't create signal handler thread ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createTrafficShaperThread(){
	if(verbose_mode)
    printf("Creating traffic shaper thread ... ");

  if(pthread_create(&trafficShaperTID, NULL, trafficShaperThread, NULL) != 0){
    printf("Can't create traffic shaper thread ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void createQueueArray(){
	if(verbose_mode)
    printf("Creating queues for communications dispatcher-threads ... ");

  dismon_queue_array = new (nothrow) ArrayQueue * [thread_number];
  if(dismon_queue_array == NULL){
    printf("Can't create queue array ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  for(i=0; i<thread_number; i++){
    dismon_queue_array[i] = new (nothrow) ArrayQueue(dismon_queue_size);
    if(dismon_queue_array[i] == NULL){
      printf("Can't create an element of queue array ! Quitting ...\n");
      exit(EXIT_FAILURE);
    }
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void initMainTID(){
	mainTID = pthread_self();
}

int get_device_index(char * device){
  FILE * f = NULL;
  int e = 0;
  int res = 0;
  char cmd[128] = { 0 };
  strcat(cmd, "cat /proc/net/pf_ring/dev/");
  strcat(cmd, device);
  strcat(cmd, "/info | grep Index | sed \"s/[^0-9]//g\"");

  f = popen(cmd, "r");
  if(f == NULL)
    return -1;

  e = fscanf(f, "%d", &res);
  if(e == 1){
    pclose(f);
    return res;
  }else{
    pclose(f);
    return -1;
  }
}

void initPFRingBundle(){
	if(verbose_mode)
    printf("Setting up pf_ring bundle ... ");
  
  if(strcmp(in_device, out_device) == 0){
    printf("Can't use the same device for IN and OUT ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }

  pfb = (pfring_bundle *)calloc(1, sizeof(pfring_bundle));
  if(pfb == NULL){
    printf("Can't create pfring_bundle ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }

  pfring_bundle_init(pfb, pick_round_robin);

  if(pfring_bundle_add(pfb, in_pfr) < 0){
    perror("Can't add to bundle IN pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }

  if(pfring_bundle_add(pfb, out_pfr) < 0){
    perror("Can't add to bundle OUT pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }

  if(verbose_mode)
    printf("DONE !\n");
}

void initPFRingIn(){
	if(verbose_mode)
    printf("Setting up pf_ring for IN device ... ");

  if(in_device == NULL)
		in_device = strdup(DEFAULT_IN_DEVICE);

  in_pfr = pfring_open(in_device, snaplen, PF_RING_LONG_HEADER | PF_RING_PROMISC);
  if(in_pfr == NULL) {
    printf("Can't open IN pf_ring ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }

  in_idx = get_device_index(in_device);
  if(in_idx == -1){
    printf("Can't find IN index ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  
  if(pfring_set_direction(in_pfr, rx_only_direction) < 0){
    perror("Can't set direction of IN pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }
  
  pfring_set_application_name(in_pfr, app_name);
  
  if(pfring_enable_ring(in_pfr) < 0){
    perror("Can't enable IN pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void initPFRingOut(){
	if(verbose_mode)
    printf("Setting up pf_ring for OUT device ... ");

  if(out_device == NULL)
		out_device = strdup(DEFAULT_OUT_DEVICE);

  out_pfr = pfring_open(out_device, snaplen, PF_RING_LONG_HEADER | PF_RING_PROMISC);
  if(out_pfr == NULL) {
    printf("Can't open OUT pf_ring ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }

  out_idx = get_device_index(out_device);
  if(out_idx == -1){
    printf("Can't find OUT index ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  
  if(pfring_set_direction(out_pfr, rx_only_direction) < 0){
    perror("Can't set direction of OUT pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }
  
  pfring_set_application_name(out_pfr, app_name);
  
  if(pfring_enable_ring(out_pfr) < 0){
    perror("Can't enable OUT pf_ring ! Quitting ...");
    exit(EXIT_FAILURE);
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void initRuleManager(){
	if(conf_file == NULL){
		printf("No configuration file specified ! Quitting ...\n");
		exit(EXIT_FAILURE);
	}
	
	if(verbose_mode)
		printf("Creating rule manager ... ");
	
	rM = new (nothrow) ruleManager(conf_file);
	
	if(rM == NULL){
		printf("Can't create rule manager ! Quitting ...\n");
		exit(EXIT_FAILURE);
	}
	
	i = rM->update_rule();
	if(i<0){
		printf("Error while parsing rule file ! Quitting ...\n");
		exit(EXIT_FAILURE);
	}
	
	if(verbose_mode)
		printf("DONE !\n");
}

void initTrafficShaper(){
  if(conf_file == NULL){
		printf("No configuration file specified ! Quitting ...\n");
		exit(EXIT_FAILURE);
	}
  
  if(verbose_mode)
    printf("Initializing traffic shaper ... ");
  
  tS = new (nothrow) trafficShaper(conf_file);
  
  if(tS == NULL){
    printf("Can't create traffic shaper ! Quitting ...\n");
    exit(EXIT_FAILURE);
  }
  
  i = tS->init_traffic_shaper();
  if(i<0){
		printf("Error while creating queue from file ! Quitting ...\n");
		exit(EXIT_FAILURE);
	}
  
  if(verbose_mode)
		printf("DONE !\n");
}

static void printHelp(){
  printf("\n\t%s - Help\n\n", APP_NAME);
  printf("\t-h              Print this help\n");
  printf("\n\tPcap mode :\n");
  printf("\t-p <file pcap>  Analyze a pcap file\n");
  printf("\n\tDevice options :\n");
  printf("\t-i <device>     IN device name (default %s)\n", DEFAULT_IN_DEVICE);
  printf("\t-o <device>     OUT device name (default %s)\n", DEFAULT_OUT_DEVICE);
  printf("\n\tRule options :\n");
  printf("\t-c <xml file>   XML file with queues and rules\n");
  printf("\n\tInternal options :\n");
  printf("\t-r <n pkt>      Size of received packet array (default %d)\n", DEFAULT_RECV_PKT_ARRAY_SIZE);
  printf("\t-q <size>       Size of each dispatcher-monitor queue (default %d)\n", DEFAULT_DISMON_QUEUE_SIZE);
  printf("\t-t <threads>    Number of threads (default %d)\n", DEFAULT_THREAD_NUMBER);
  printf("\n\tHash table options :\n");
  printf("\t-s <size>       Size of each hash table (default %d)\n", DEFAULT_HASH_TABLE_SIZE);
  printf("\t-u <n pkt>      Packet interval to update hash table (default %d)\n", DEFAULT_UPDATE_HT_PKT_INTERVAL);
  printf("\n\tDetection options :\n");
  printf("\t-l <n pkt>      Packet limit for detecting protocol (default %d)\n", DEFAULT_N_PKT_LIMIT);
  printf("\n\tShaper options :\n");
  printf("\t-d <n pkt>      Number of packet to send before wait (default %d)\n", DEFAULT_PKT_TO_SEND);
  printf("\t-w <ns>         Nanoseconds to wait (default %d)\n", DEFAULT_NS_TO_WAIT);
  printf("\n\tVerbose mode :\n");
  printf("\t-v              Verbose mode ON\n");
  printf("\n");
}

void setPreferences(int argc, char * argv[]){
	char c;
	
	while((c = getopt(argc,argv,"hp:i:o:c:r:q:t:s:u:l:d:w:v")) != '?'){
    if((c == 255) || (c == -1)) break;

    switch(c){
			case 'h':
				printHelp();
				exit(EXIT_SUCCESS);
				break;
			case 'p':
				analyzePcapFile(optarg);
				exit(EXIT_SUCCESS);
				break;
			case 'i':
				in_device = strdup(optarg);
				break;
			case 'o':
				out_device = strdup(optarg);
				break;
			case 'c':
        conf_file = strdup(optarg);
				break;
			case 'r':
				recv_pkt_array_size = atoi(optarg);
				break;
      case 'q':
				dismon_queue_size = atoi(optarg);
				break;
      case 't':
				thread_number = atoi(optarg);
				break;
			case 's':
				hash_table_size = atoi(optarg);
				break;
			case 'u':
				update_hash_table_interval = atoi(optarg);
				break;
			case 'l':
				n_pkt_limit = atoi(optarg);
				break;
      case 'd':
        pkt_to_send = atoi(optarg);
        break;
      case 'w':
        time_to_wait.tv_nsec = atoi(optarg);
        break;
			case 'v':
				verbose_mode = true;
				setbuf(stdout, NULL);
				break;
    }
  }
  
  app_name = strdup(APP_NAME);
}
