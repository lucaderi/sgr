#include "utils.h"
#include "flow.h"
#include "stats.h"
#include "rrdstats.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#ifdef linux
#include <netinet/ether.h>
#endif
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netdb.h>
#include <sys/stat.h>
#include <pthread.h>

/* CONFIGURATION */
#define PROMISC 1
#define TIMEOUT 1500
#define CAPSIZE 65535
#define BUFSTRING 128
#define LOOPCOUNT -1
#define DEFAULT_RRD_NAME "rrddata.rrd"
/*#define DEBUG*/

/* CONTROL PARAMETERS */
char *dev = NULL;
char *pcap_f = NULL;
int inout_traffic_control = FALSE;
int rrdtool = FALSE;
int flow = FALSE;
int verbose = FALSE;

/* FLOW PARAMETERS */
/* lockless queues used to pass packets to flow managing threads */
queue_t q[QUEUE_NO];
/* arguments for flow managing threads */
flow_processor_args_t flow_args[QUEUE_NO];

/* RRD PARAMETERS */
rrd_update_args_t rrd_args;

/* STATS */
/* Total no of packets captured */
u_int pkts_tot = 0;
int errors = 0;

/* CAPTURE PARAMETERS */
/* Stat structure to be update analyzing current packet */
stats_t *stats;
/* Datalink id */
int datalink = 0;
/* Layer 2 header lenght */
int header_len = 0;
/* Layer 3 header lenght */
int network_len = 0;
/* Packet dimansion without layer 2 header */
int p_size = 0;
/* mac address of the capturing device */
u_char mac[6];
/* current decoded packet for flow analisys */
pkt_t pdecode;
