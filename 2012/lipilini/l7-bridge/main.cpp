#include "globals.h"

// variables from globals.h
char * app_name = NULL;

const char * protocol_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

volatile sig_atomic_t exit_condition = 0;

// hash table global variables
u_int32_t hash_table_size = DEFAULT_HASH_TABLE_SIZE; 
u_int32_t update_hash_table_interval = DEFAULT_UPDATE_HT_PKT_INTERVAL; 

// PF_RING global variables
char * in_device = NULL; 
pfring * in_pfr = NULL;
int in_idx = -1;
char * out_device = NULL; 
pfring * out_pfr = NULL;
int out_idx = -1;
pfring_bundle * pfb = NULL;
int snaplen = DEFAULT_SNAPLEN;

// rule manager global variables
ruleManager * rM = NULL;

char * conf_file = NULL;

// traffic shaper global variables
trafficShaper * tS = NULL;
u_int32_t pkt_to_send = DEFAULT_PKT_TO_SEND;
struct timespec time_to_wait = DEFAULT_TIME_TO_WAIT;

// thread global variables
pthread_t mainTID = 0;
pthread_t signalHandlerTID = 0;
pthread_t trafficShaperTID = 0;
u_int8_t thread_number = DEFAULT_THREAD_NUMBER; 
pthread_t * pthread_array = NULL;
int * local_tid_array = NULL;
flowHashTable ** hash_table_array = NULL;
struct ipoque_detection_module_struct ** ipoque_struct_array = NULL;
u_int32_t n_pkt_limit = DEFAULT_N_PKT_LIMIT; 

ArrayQueue ** dismon_queue_array = NULL;
u_int32_t dismon_queue_size = DEFAULT_DISMON_QUEUE_SIZE;

recv_pkt_t * recv_pkt_array = NULL;
u_int32_t recv_pkt_array_size = DEFAULT_RECV_PKT_ARRAY_SIZE; 

// operating modes
bool verbose_mode = false;

static void forward_pkt(int32_t _rx_ifid, u_int32_t _len, u_char * _pkt){
  int e = 0;
  
  if(_rx_ifid == in_idx){
		e = pfring_send(out_pfr, (char *)_pkt, _len, 1);
		if(e < 0){
			printf("[ dispatcher ] Can't send non-IP packet to OUT ...\n");
		}else{
			if(verbose_mode)
				printf("[ dispatcher ] Sent %d bytes of non-IP to OUT !\n", e);
		}
  }else{
		e = pfring_send(in_pfr, (char *)_pkt, _len, 1);
		if(e < 0){
			printf("[ dispatcher ] Can't send non-IP packet to IN ...\n");
		}else{
			if(verbose_mode)
				printf("[ dispatcher ] Sent %d bytes of non-IP to IN !\n", e);
		}
  }
  
  return;
}

static __inline__ u_int8_t which_thread_v4(ip_addr * _src_ip, ip_addr * _dst_ip){
  return (u_int8_t) ((_src_ip->v4 + _dst_ip->v4) % thread_number);
}

static __inline__ u_int8_t which_thread_v6(ip_addr * _src_ip, ip_addr * _dst_ip){
  return (u_int8_t) ((sum_ipv6(_src_ip->v6) + sum_ipv6(_dst_ip->v6)) % thread_number);
}

int main(int argc, char *argv[]){
	int e = 0;
	u_int8_t j = 0;
  bool b = false;
	u_int32_t last_recv_pkt = 0;
  recv_pkt_t * pRP = NULL;
	
  pfring_pkthdr tmpHdr;
  u_char * tmpPkt = NULL;
  
	// mask all signal
	sigset_t set;
	sigfillset(&set);
	pthread_sigmask(SIG_SETMASK, &set, NULL);
	
	// setting preferences
	setPreferences(argc, argv);
	
	// initialization phase
	if(verbose_mode)
		printf("\nInitializing system ...\n\n");
	
	initMainTID();
	
  initTrafficShaper();
  createTrafficShaperThread();
	initRuleManager();
	
	createSignalHandlerThread();	
	
	createLocalTIDArray();
	createFlowHTArray();
	createIPQDetStructArray();
	createQueueArray();
	createMonitorThreads();
	
	createRecvPktArray();
	
	initPFRingIn();
	initPFRingOut();
	initPFRingBundle();
	
	if(verbose_mode)
		printf("\nINITIALIZATION DONE !\n\nWaiting for packets ...\n\n");
	
	
	// dispatching loop
	while(!exit_condition){
    // wait for incoming packet
    e = pfring_bundle_read(pfb, &tmpPkt, 0, &tmpHdr, 1);
    
    // an error occurs
    if(e <= 0){
      if(exit_condition == 0){
        printf("[ dispatcher ] Error while reading packet or timeout occurs ! Retrying ...\n");
        continue;
      }else{
        break;
      }
    }
    
    // directly forward non-IP traffic, i.e. ARP ...
    // directly forward non-TCP and non-UDP traffic
    if(tmpHdr.extended_hdr.parsed_pkt.ip_version == 0 ||
            (tmpHdr.extended_hdr.parsed_pkt.l3_proto != IPPROTO_TCP && tmpHdr.extended_hdr.parsed_pkt.l3_proto != IPPROTO_UDP)){
      
      forward_pkt(tmpHdr.extended_hdr.if_index, tmpHdr.caplen, tmpPkt);
      
      continue;
    }

    // have to dispatch packet, so search for an unused element in received packet array ...
    while(1){
      last_recv_pkt++;

      if(last_recv_pkt == recv_pkt_array_size)
				last_recv_pkt = 0;

      if(!ATOMIC_TSL(&(recv_pkt_array[last_recv_pkt].in_use)))
				break;
    }
    
    pRP = &(recv_pkt_array[last_recv_pkt]);
    
    // ... and fill received packet array slot with info and real packet
    pRP->_rx_if_index = tmpHdr.extended_hdr.if_index;
    pRP->_caplen = tmpHdr.caplen;
    pRP->_l3_offset = tmpHdr.extended_hdr.parsed_pkt.offset.l3_offset;
    pRP->_pkt_ts = tmpHdr.ts;
    
    pRP->_ip_version = tmpHdr.extended_hdr.parsed_pkt.ip_version;
    pRP->_ip_proto = tmpHdr.extended_hdr.parsed_pkt.l3_proto;
    pRP->_src_ip = tmpHdr.extended_hdr.parsed_pkt.ip_src;
    pRP->_src_port = tmpHdr.extended_hdr.parsed_pkt.l4_src_port;
    pRP->_dst_ip = tmpHdr.extended_hdr.parsed_pkt.ip_dst;
    pRP->_dst_port = tmpHdr.extended_hdr.parsed_pkt.l4_dst_port;
    
    pRP->_n_bytes = tmpHdr.caplen - tmpHdr.extended_hdr.parsed_pkt.offset.l3_offset;
    
    memcpy(pRP->p, tmpPkt, tmpHdr.caplen);
		
    // calculating thread id J
    j = (pRP->_ip_version == 4) ? which_thread_v4(&(pRP->_src_ip), &(pRP->_dst_ip)) : which_thread_v6(&(pRP->_src_ip), &(pRP->_dst_ip));
      
    // queue index in received packet array to thread J
		b = dismon_queue_array[j]->Enqueue(pRP);
    
    if(b){
      if(verbose_mode)
        printf("[ dispatcher ] New packet captured ! Stored in slot %d, enqueued to monitor thread %d ...\n", last_recv_pkt, j);
    }else{
      // problem with queuing packet !
      printf("[ dispatcher ] Can't enqueue a new packet captured to monitor thread %d ! Dropped !\n", j);
      
      ATOMIC_RL(&(pRP->in_use));
    }

  }
  
	if(verbose_mode)
		printf("\nTerminating system ...\n\n");
  
	// termination phase
	waitSignalHandlerThread();
	
	destroyMonitorThreads();
	destroyQueueArray();
	destroyIPQDetStructArray();
	destroyFlowHTArray();
	destroyLocalTIDArray();
	
	destroyRecvPktArray();
  
  termRuleManager();
  destroyTrafficShaperThread();
  termTrafficShaper();
	
	termPFRingIn();
	termPFRingOut();
	termPFRingBundle();
	
	
	if(verbose_mode)
		printf("\nSYSTEM TERMINATED ! BYE !\n\n");
	
	exit(EXIT_SUCCESS);
}
