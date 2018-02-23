#include "analyzer.h"

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <ncurses.h>

#include "formats.h"
#include "libs/uthash/uthash.h"

#define CLEAR_SCREEN for (int asdfghjkl=0; asdfghjkl<20; asdfghjkl++) printf("\n");


// ----- ----- GLOBALS ----- ----- //
long gTotPackets = 1;


// ----- ----- STRCUTS ----- ----- //
struct _HostDetails {
  long pSend;
  unsigned char hostIP[4];
  unsigned char hostMAC[6];

  unsigned long ID;
  UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct _HostDetails HostDetails;

HostDetails* devicesTable = NULL; // Declaring hashtable


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
static void printDevStat();


// ----- ----- ANALYZING ----- ----- //
void Analyze(int caplen, const uint8_t *bytes) {
  printDevStat();

  // Gathering host info
  EthHeader* eth = (EthHeader*) bytes;
  char aus[20]; stringFyMAC(aus, eth->srcAddr);
  unsigned long devID = hashString((unsigned char*) aus);

  unsigned char* hostIP = NULL;
  if(eth->type == IP_PROTO) {
    IpHeader* ipFrame = (IpHeader*) (bytes + 14); // 14 Byte Ethernet header
    hostIP = ipFrame->srcIP;
  }

  HostDetails* device;
  HASH_FIND_INT(devicesTable, &devID, device);
  if(device == NULL){
    // New host discovered
    device = (HostDetails*) malloc(sizeof(HostDetails));

    device->pSend = 0;
    device->ID = devID;
    memcpy(device->hostMAC, eth->srcAddr, 6);
    if(hostIP != NULL) memcpy(device->hostIP, hostIP, 4);

    HASH_ADD_INT(devicesTable, ID, device);  /* id: name of key field */
  }
  else {
    // Known host, updating statics
    gTotPackets++;
    device->pSend = device->pSend + 1;
    if(hostIP != NULL) memcpy(device->hostIP, hostIP, 4);
  }
}


// ----- ----- DISPLAYING STATICS ----- ----- //
static void printDevStat() {
  clear();
  printw("Tot packets: %ld\n", gTotPackets);
  for(HostDetails* currentDev=devicesTable; currentDev != NULL; currentDev=currentDev->hh.next) {
    char devMac[25];
    stringFyMAC(devMac, currentDev->hostMAC);

    char devIP[25];
    stringFyIP(devIP, currentDev->hostIP);

    float perc = ((float) currentDev->pSend/gTotPackets);

    printw("Device:   MAC/%s   IP/%s   %%(%.4f)\n", devMac, devIP, perc);
  }
  refresh();
}


// ----- ----- CLEANING ENVIRONMENT ----- ----- //
void cleanAnalyzer() {
  if(devicesTable == NULL) return;

  HostDetails *currentDev, *tmp;

  HASH_ITER(hh, devicesTable, currentDev, tmp) {
    HASH_DEL(devicesTable, currentDev);
    free(currentDev);
  }
}
