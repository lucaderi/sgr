#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd;
int verbose = 0;
struct pcap_stat pcapStats;
char *device = NULL;


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include "structure.h"

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;

/* inizializzo il numero identificativo del pacchetto */
uint16_t packet_id = -1;

/* *************************************** */

int32_t gmt_to_local(time_t t) {
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

int drop_privileges(const char *username) {
  struct passwd *pw = NULL;

  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return -1;
  }

  pw = getpwnam(username);

  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  if(pw != NULL) {
    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
      fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
      return -1;
    } else {
      fprintf(stderr, "user changed to %s\n", username);
    }
  } else {
    fprintf(stderr, "unable to locate user %s\n", username);
    return -1;
  }

  umask(0);
  return 0;
}

static int32_t thiszone;
int count = 0;
void dummyProcesssPacket(unsigned char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const unsigned char *p) {

  struct ip_header_* hrd = (struct ip_header_*)(p + sizeof(struct eth_header));

  /*
    verifico che sia un pacchetto udp e che abbia l'idenfificativo
    indicato nellariga di comando       
  */

  if(hrd->protocol == 17 && hrd->identification == packet_id){
    if(h->caplen < SIZE_PACKET){
      printf("Errore nella cattura dei byte del pacchetto\n");
      return;
    }

    /*
      vado a copiare il conteuto del pacchetto per incrementare l'hop
    */
    unsigned char* cpy = malloc(h->caplen);
    memcpy(cpy, p, h->caplen);
    struct payload* payload = (struct payload*)(cpy + sizeof(struct eth_header)+
              sizeof(struct ip_header_) + sizeof(struct udp_header_));
    printf("hop: %d\n", payload->hop);

    payload->hop++;

    count++;
    printf("===================\ncounter: %d\n",count);
    printf("pacchetto arrivato!\n");
  
    int send = pcap_sendpacket(pd, cpy, 
          h->caplen);
          if(send != 0){
            fprintf(stderr, "Errore invio pacchetto: %s\n", pcap_geterr(pd));
          } else {
            printf("pacchetto inoltrato\n");
          }
          printf("===================\n\n");
  } else {

    /*
      ricezione di un pacchetto del normale traffico di rete
    */
    count++;
    printf("===================\ncounter: %d\n",count);
    printf("pacchetto arrivato!\n");
  
    int send = pcap_sendpacket(pd, p, 
          h->caplen);
          if(send != 0){
            fprintf(stderr, "Errore invio pacchetto: %s\n", pcap_geterr(pd));
          } else {
            printf("pacchetto inoltrato\n");
          }
          printf("===================\n\n");
  }
   
  
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-d <flagIdPacket> [flag identification packet]\n");
  printf("-f <filter>      [pcap filter]\n");
  printf("-w <path>        [pcap write file]\n");  
  printf("-d <num>        [packet id]\n");  
  printf("-l <len>         [Capture length]\n");
  printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    printf("\nAvailable devices (-i):\n");
    while(devpointer) {
      const char *descr = devpointer->description;

      if(descr)
	printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
      else
	printf(" %d. %s\n", i++, devpointer->name);
      
      devpointer = devpointer->next;
    }
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *bpfFilter = NULL;
  unsigned char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  struct stat s;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc, argv, "hi:d:l:v:f:w:")) != '?') {
    if((c == 255) || (c == (unsigned char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    case 'i':
      device = strdup(optarg);
      break;
    case 'd':
      packet_id = (uint16_t)atoi(strdup(optarg));
      break;

    case 'l':
      snaplen = atoi(optarg);
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'w':
      dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg);
      if(dumper == NULL) {
        printf("Unable to open dump file %s\n", optarg);
        return(-1);
      }
      break;

    case 'f':
      bpfFilter = strdup(optarg);
      break;
    }
  }
  
  if(geteuid() != 0) {
    printf("Please run this tool as superuser\n");
    return(-1);
  }
  
  if(device == NULL) {
    printf("ERROR: Missing -i\n");    
    printHelp();
    return(-1);  
  }

  printf("Capturing from %s\n", device);

  if(stat(device, &s) == 0) {
    /* Device is a file on filesystem */
    if((pd = pcap_open_offline(device, errbuf)) == NULL) {
      printf("pcap_open_offline: %s\n", errbuf);
      return(-1);
    }
  } else {
    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1;
    if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
  }
  if(bpfFilter != NULL) {
    if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
    }
  }

  if(drop_privileges("nobody") < 0)
    return(-1);
  
  /*signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }*/

  pcap_loop(pd, -1, dummyProcesssPacket, NULL);

  

  pcap_close(pd);

  if(dumper)
    pcap_dump_close(dumper);
  
  return(0);
}
