#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <stdbool.h>
#include <getopt.h>
#include <netinet/ether.h>
#include "utils_leaky_bucket.h"


#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd, *pd2;
char* device = NULL;
char* dev2 = NULL;
int verbose = 0;
struct pcap_stat pcapStats;

/* IDENTIFICATIVO DEL PACCHETTO INVIATO DA SENDER.C */
uint16_t packet_id = -1;

#include <arpa/inet.h>
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


static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;

/* DEFINIZIONE DELLE LISTE */
struct Bucket* table[SIZE] = {0};
struct Address_node* blacklist[SIZE] = {0};

/* CONTATORE DEI PACCHETTI */
int counter_packets = 0;

void print_ip32(uint32_t ip);

void print_bucket(struct Bucket** table);
void print_blacklist(struct Address_node** blacklist);
uint8_t hash(uint32_t ip);

long int calc_rem(struct Bucket* b);

void update_blacklist(uint8_t index, struct Address_node** blacklist);
bool ipInBlacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist);

void check_bucket(struct Bucket** table, struct Address_node** blacklist);

void free_buckets(struct Bucket** table);

void free_blacklist(struct Address_node** blacklist);
void process_packet(unsigned char* user,
    const struct pcap_pkthdr* h,
    const unsigned char* packet, pcap_t* in, pcap_t* out,
    struct Bucket** table, struct Address_node** blacklist,
    char* dev1, char* dev2);

void insert_ip_in_blacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist);


/*FINE DEFINIZIONE STRUTTURE LEACKY BUCKET*/

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

/* ****************************************************** */

static int32_t thiszone;


/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: mybridge -i <device|path>  -o <device|path> -d <flagIdPacket> \n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-o <device|path> [Device name or file path]\n");
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
  char*bpfFilter = NULL;
  unsigned char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  struct stat s;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc, argv, "hi:o:d:l:v:f:w:")) != '?') {
    if((c == 255) || (c == (unsigned char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    
    case 'i':
      device = strdup(optarg);
      break;
    case 'o':
      dev2 = strdup(optarg);
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

  if(dev2 == NULL){
    printf("ERROR: Missing -o\n");    
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
    if((pd2 = pcap_open_live(dev2, snaplen, promisc, 500, errbuf)) == NULL) {
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

  if(pcap_setdirection(pd, PCAP_D_IN) < 0){
    fprintf(stderr, "error set direction: %s\n", pcap_geterr(pd));
  }
  if(pcap_setdirection(pd2, PCAP_D_IN) < 0){
    fprintf(stderr, "error set direction: %s\n", pcap_geterr(pd2));
  }

  int fd_in = pcap_get_selectable_fd(pd);
  int fd_out = pcap_get_selectable_fd(pd2);

  fd_set readsfd;

  while(1){

    FD_ZERO(&readsfd);
    FD_SET(fd_in, &readsfd);
    FD_SET(fd_out, &readsfd);

    int max = (fd_in > fd_out) ? fd_in : fd_out;

    if(select(max+1, &readsfd, NULL, NULL, NULL) > 0){
        if(FD_ISSET(fd_in, &readsfd)){
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(pd, &header, &packet);

            // un pacchetto ethernet deve essere lungo almeno 14 byte
            if(res > 0 && header->caplen >= sizeof(struct ether_header)){
              struct ether_header eth;
              memcpy(&eth, packet, sizeof(struct ether_header));
              uint16_t type = ntohs(eth.ether_type);
              printf("[%s] arrivato il pacchetto\n", device);

              if(type == ETHERTYPE_IP){

                struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));

                struct in_addr src;
                src.s_addr = ip->saddr;

                printf("[%s] pacchetto arrivato da %s!\n", device, inet_ntoa(src));
                
                process_packet(NULL, header, packet, pd, pd2, table, blacklist,
                device, dev2); 
                counter_packets++;
                printf("----------------------------------");
                printf("\n=========STATS=========\n");
                printf("Packet #%d\n", counter_packets);
                printf("IP: %s\n", inet_ntoa(src));
                printf("=======================\n\n");
                printf("=========LINKED LISTS=========\n\n");
                print_bucket(table);
                printf("\n");
                print_blacklist(blacklist);
                printf("\n=============================\n\n");

              }
            }
        }

        if(FD_ISSET(fd_out, &readsfd)){
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(pd2, &header, &packet);
            
            if(res > 0 && header->caplen >= sizeof(struct ether_header)){
              struct ether_header eth;
              memcpy(&eth, packet, sizeof(struct ether_header));
              uint16_t type = ntohs(eth.ether_type);
              printf("[%s] arrivato il pacchetto\n", dev2);

              if(type == ETHERTYPE_IP){

                struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));

                struct in_addr src;
                src.s_addr = ip->saddr;

                printf("[%s] pacchetto arrivato da %s!\n", dev2, inet_ntoa(src));
                
                if(pcap_sendpacket(pd2, packet, header->caplen) != 0){
                  printf("errore nell'invio del pacchetto: %s!\n",pcap_geterr(pd2));
                } else {
                  printf("[%s] inviato a [%s]\n", device, dev2);
                }

              }


              
            }
        }
    }

  }

  free_blacklist(blacklist);
  free_buckets(table);



  //pcap_loop(pd, -1, dummyProcesssPacket, NULL);

  pcap_close(pd);

  if(dumper)
    pcap_dump_close(dumper);
  
  return(0);
}
