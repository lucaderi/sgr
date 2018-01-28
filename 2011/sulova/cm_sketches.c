
#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "countmin.h"

#define ALARM_SLEEP             60
#define DEFAULT_SNAPLEN        128
#define MAX_NUM_THREADS         64
#define DEFAULT_DEVICE      "eth0"


pfring  *pd;

int num_threads = 1;
int num_heavy_hitters = 10;
uint32_t *heap;

int width=512,depth=5;
float phi = 0.05;
unsigned long long thresh;
CM_type * cm;


pfring_stat pfringStats;
pthread_rwlock_t statsLock;

static struct timeval startTime;
unsigned long long numPkts[MAX_NUM_THREADS] = { 0 }, numBytes[MAX_NUM_THREADS] = { 0 };
u_int8_t wait_for_packet = 1, do_shutdown = 0;


char* intoa(unsigned int addr);

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(pfring_stats(pd, &pfringStat) >= 0) {
    double thpt;
    int i;
    unsigned long long nBytes = 0, nPkts = 0;

    for(i=0; i < num_threads; i++) {
      nBytes += numBytes[i];
      nPkts += numPkts[i];
    }

    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
	    (unsigned int)(pfringStat.recv+pfringStat.drop),
	    pfringStat.recv == 0 ? 0 :
	    (double)(pfringStat.drop*100)/(double)(pfringStat.recv+pfringStat.drop));
    fprintf(stderr, "%llu pkts - %llu bytes", nPkts, nBytes);

    fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n",
	      (double)(nPkts*1000)/deltaMillisec, thpt);
    
    fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	      (long long unsigned int)diff,
	      deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)));
    }

    lastPkts = nPkts;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
  
  // Strampa i Heavy Hitters
  int i;
  // il 10 deve essere un parametro di input
  printf("[heavy hitters  -> %d ] \n", num_heavy_hitters);
  for (i = 0; i<num_heavy_hitters;i++){
   
     printf("%d [heavy hitter -> %s con numero pacchetti -> %d] \n",
            i,intoa(heap[i]), CM_PointEst(cm,heap[i]));
  }
  free(heap);
}

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  if(num_threads == 1)
    pfring_close(pd);

  exit(0);
}

/* ******************************** */

/* ******************************** */
/*Vedi se il limite di 60 secondi è scatato.*/
void my_sigalarm(int sig) {
  //print_stats();
  alarm(ALARM_SLEEP);
  sigproc(1);
}
/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}


char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
  long threadId = (long)user_bytes;

    
  struct ether_header ehdr;
  u_short eth_type;
  struct ip ip;
 

  if(h->ts.tv_sec == 0) {
    gettimeofday((struct timeval*)&h->ts, NULL);
    parse_pkt((u_char*)p, (struct pfring_pkthdr*)h);
  }
    
  memcpy(&ehdr, p+h->extended_hdr.parsed_header_len, sizeof(struct ether_header));
  eth_type = ntohs(ehdr.ether_type);

 
  //Only ip traffic
  if(eth_type == 0x0800) {
    memcpy(&ip, p+h->extended_hdr.parsed_header_len+sizeof(ehdr), sizeof(struct ip));
    printf("[%s]", proto2str(ip.ip_p));
    printf("[%s:", intoa(ntohl(ip.ip_src.s_addr)));
    printf("-> %s] \n", intoa(ntohl(ip.ip_dst.s_addr)));

    numPkts[threadId]++, numBytes[threadId] += h->len;
  
    unsigned long long nBytes = 0, nPkts = 0;
      
    int i; 
    for(i=0; i < num_threads; i++) {
      nBytes += numBytes[i];
      nPkts += numPkts[i];
    }
      
    unsigned long long  ipLongNumber = ntohl(ip.ip_src.s_addr);

    CM_Update(cm,ipLongNumber,1);
    
    int min = CM_PointEst(cm,heap[0]);
    int index = 0;
    int hasZero = 0;
      
    for (i = 0; i < num_heavy_hitters;i++){
        
      if ((heap[i] == ipLongNumber) || 
                      (CM_PointEst(cm,heap[i]) < (phi*nPkts))){
          heap[i] = (uint32_t)0 ;
          hasZero = 1;
      }
    }
      
    if (CM_PointEst(cm,ipLongNumber) > (phi*nPkts)){
    //aggiungi la ntohl(ip.ip_src.s_addr) nello heap
      if (hasZero == 1){
        int j;
        for (j = 0; j < num_heavy_hitters; j++){
           if(heap[j] == (uint32_t)0){
             heap[j] = ipLongNumber;
             break;
           }      
        }
      }
      else{
        //Non ho trovato un posto libero nello heap.
        //Vedo se è maggiore del minimo di quelli contenuti nello heap.
        
        for (i = 0; i < num_heavy_hitters;i++){
          if (CM_PointEst(cm,heap[i]) < min){
            min = CM_PointEst(cm,heap[i]);
            index = i;
          }
        }
           
        if (CM_PointEst(cm,ipLongNumber) > min){
           heap[index] = ipLongNumber;
        }
      }
    }
  } 
}


/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* *************************************** */

void printHelp(void) {
  printf("Count Min Sketches \n\n\n");
  printf("-h                   Print this help\n");
  printf("-i <device>          Device name. Use device@channel for channels, and dna:ethX for DNA\n");
  
  printf("-n <threads>         Number of polling threads (default %d)\n", num_threads);

  /* printf("-f <filter>     [pfring filter]\n"); */

  printf("-e <direction>       0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-a                   Active packet wait\n");
  printf("-p <threshold>       phi threshold for heavy hitter items.  Default = 0.01\n");
  printf("-w <width>           width of sketch to keep. Default = 512\n");
  printf("-d <depth>           depth of sketch to keep. Default = 5\n");
  printf("-x <heavy hitters>   max number of heavy hitter items. Default 10.\n");
}

/* *************************************** */

/* Bind this thread to a specific core */

int bind2core(u_int core_id) {
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    printf("Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
}

/* *************************************** */

void* packet_consumer_thread(void* _id) {
  long thread_id = (long)_id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  u_char *buffer;

  u_long core_id = thread_id % numCPU;
  struct pfring_pkthdr hdr;

  /* printf("packet_consumer_thread(%lu)\n", thread_id); */

  if((num_threads > 1) && (numCPU > 1)) {
    if(bind2core(core_id) == 0)
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
  }

  memset(&hdr, 0, sizeof(hdr));

  while(1) {
    if(do_shutdown) break;

    if(pfring_recv(pd, &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      dummyProcesssPacket(&hdr, buffer, (u_char*)thread_id);

    } else {
      if(wait_for_packet == 0) sched_yield();
    }
  }
  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, buf[32];
  u_char mac_address[6];
  int promisc, snaplen = DEFAULT_SNAPLEN,rc;
  int bind_core = -1;
  packet_direction direction = rx_and_tx_direction;
  
  startTime.tv_sec = 0;
  thiszone = gmt2local(0);

  while((c = getopt(argc,argv,"hi:dae:n:p:w:d:x:" /* "f:" */)) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction:
      case rx_only_direction:
      case tx_only_direction:
	direction = atoi(optarg);
	break;
      }
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'n':
      num_threads = atoi(optarg);
      break;
    case 'p':
      phi = atof(optarg);
    case 'w':
      width = atoi(optarg);
    case 'd':
      depth = atoi(optarg);
    case 'x':
      num_heavy_hitters = atoi(optarg);
    }
  }
  
  if(device == NULL) device = DEFAULT_DEVICE;
  if(num_threads > MAX_NUM_THREADS) num_threads = MAX_NUM_THREADS;

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;

  if(num_threads > 0)
    pthread_rwlock_init(&statsLock, NULL);

  if (num_heavy_hitters > 0)
    heap =(uint32_t *)malloc(num_heavy_hitters * sizeof(uint32_t));
  else
    heap =(uint32_t *)malloc(10 * sizeof(uint32_t));
  int i = 0;
  for (i = 0; i<num_heavy_hitters; i++){
    heap[i] = 0;
  }
  
  pd = pfring_open(device, promisc,  snaplen, (num_threads > 1) ? 1 : 0);

  if(pd == NULL) {
    printf("pfring_open error (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n",
	   device);
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "cm_sketches");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  if(pfring_get_bound_device_address(pd, mac_address) != 0)
    printf("pfring_get_bound_device_address() failed\n");
  else
    printf("Capturing from %s [%s]\n", device, etheraddr_string(mac_address, buf));

  
  printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd));
  printf("# Polling threads:    %d\n", num_threads);
  
  pfring_enable_ring(pd);
  
  
  if((rc = pfring_set_direction(pd, direction)) != 0)
    printf("pfring_set_direction returned [rc=%d][direction=%d]\n", rc, direction);

  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);


  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);
  
  
 
  if(num_threads > 1) {
    pthread_t my_thread;
    long i;

    for(i=1; i<num_threads; i++)
      pthread_create(&my_thread, NULL, packet_consumer_thread, (void*)i);

    bind_core = -1;
  }
  if(bind_core >= 0)
    bind2core(bind_core);
  
  // 12 è un numero qualsiasi, necessario per generare numeri random
  // nelle procedure degli sketches
  cm=CM_Init(width,depth,12);


  if(1) {
    pfring_loop(pd, dummyProcesssPacket, (u_char*)NULL);
  } else
    packet_consumer_thread(0);


  sleep(1);
  pfring_close(pd);

  return(0);
}
