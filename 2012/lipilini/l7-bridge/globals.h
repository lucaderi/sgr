#ifndef _GLOBALS_H_
#define _GLOBALS_H_

// common include
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <new>
#include <pthread.h>
#include <unistd.h>

// my include
#include "globalTypes.h"

#include "flowHashTable.h"
#include "ruleManager.h"
#include "trafficShaper.h"

#include "atomic.h"
#include "flowUtil.h"
#include "ipUtil.h"
#include "mathUtil.h"
#include "memUtil.h"
#include "timeUtil.h"

#include "arrayQueue.h"

// other include

#include "pfring.h"
#include "ipq_api.h"


// global define
#define APP_NAME "l7-bridge"
extern char * app_name;

#define DEFAULT_IN_DEVICE "eth0"
#define DEFAULT_OUT_DEVICE "eth1"

#define DEFAULT_THREAD_NUMBER 4
#define DEFAULT_RECV_PKT_ARRAY_SIZE 4096
#define DEFAULT_DISMON_QUEUE_SIZE (DEFAULT_RECV_PKT_ARRAY_SIZE / DEFAULT_THREAD_NUMBER)

#define DEFAULT_HASH_TABLE_SIZE 10000
#define DEFAULT_UPDATE_HT_PKT_INTERVAL (DEFAULT_HASH_TABLE_SIZE / 2)

#define DEFAULT_PKT_TO_SEND 1000
#define DEFAULT_NS_TO_WAIT 1000
#define DEFAULT_TIME_TO_WAIT { 0, DEFAULT_NS_TO_WAIT }

#define DEFAULT_TICK_RESOLUTION 1000
#define DEFAULT_N_PKT_LIMIT 30


extern const char * protocol_long_str[];

extern volatile sig_atomic_t exit_condition;


// hash table global variables
extern u_int32_t hash_table_size; // DEFINED BY USER
extern u_int32_t update_hash_table_interval; // DEFINED BY USER

// PF_RING global variables
extern char * in_device; // DEFINED BY USER
extern pfring * in_pfr;
extern int in_idx;
extern char * out_device; // DEFINED BY USER
extern pfring * out_pfr;
extern int out_idx;
extern pfring_bundle * pfb;
extern int snaplen;

// rule manager global variables
extern ruleManager * rM;

extern char * conf_file; // DEFINED BY USER

// traffic shaper global variables
extern trafficShaper * tS;
extern u_int32_t pkt_to_send;
extern struct timespec time_to_wait;

// thread global variables
extern pthread_t mainTID;
extern pthread_t signalHandlerTID;
extern pthread_t trafficShaperTID;
extern u_int8_t thread_number; // DEFINED BY USER
extern pthread_t * pthread_array;
extern int * local_tid_array;
extern flowHashTable ** hash_table_array;
extern struct ipoque_detection_module_struct ** ipoque_struct_array;
extern u_int32_t n_pkt_limit; // DEFINED BY USER

extern ArrayQueue ** dismon_queue_array;
extern u_int32_t dismon_queue_size;

extern recv_pkt_t * recv_pkt_array;
extern u_int32_t recv_pkt_array_size; // DEFINED BY USER

// operating modes
extern bool verbose_mode; // DEFINED BY USER

// init functions
extern void createRecvPktArray();
extern void createFlowHTArray();
extern void createIPQDetStructArray();
extern void createLocalTIDArray();
extern void createMonitorThreads();
extern void createSignalHandlerThread();
extern void createTrafficShaperThread();
extern void createQueueArray();
extern void initMainTID();
extern void initPFRingBundle();
extern void initPFRingIn();
extern void initPFRingOut();
extern void initRuleManager();
extern void initTrafficShaper();
extern void setPreferences(int argc, char * argv[]);

// termination functions
extern void destroyRecvPktArray();
extern void destroyFlowHTArray();
extern void destroyIPQDetStructArray();
extern void destroyLocalTIDArray();
extern void destroyMonitorThreads();
extern void waitSignalHandlerThread();
extern void destroyTrafficShaperThread();
extern void destroyQueueArray();
extern void termPFRingBundle();
extern void termPFRingIn();
extern void termPFRingOut();
extern void termRuleManager();
extern void termTrafficShaper();

// thread functions
extern void * monitorThread(void * arg);
extern void * signalHandlerThread(void * arg);
extern void * trafficShaperThread(void * arg);

// pcap analyzer functions
extern void analyzePcapFile(char * _pcap_file);

#endif // _GLOBALS_H_
