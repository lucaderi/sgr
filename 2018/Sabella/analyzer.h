#ifndef ANALYZER_H
#define ANALYZER_H

#include <limits.h>
#include "libs/uthash/uthash.h"

#define CLEAR_SCREEN for (int asdfghjkl=0; asdfghjkl<20; asdfghjkl++) printf("\n");


// ----- ----- GLOBALS ----- ----- //
long gTotPackets = 1;


// ----- ----- STRCUTS ----- ----- //
struct DevStatics {
  long pSend;
  unsigned char hostIP[4];
  unsigned char hostMAC[6];

  unsigned long devID;
  UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct DevStatics DevStatics;

DevStatics* devicesTable = NULL; // Declaring hashtable


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
unsigned long hashMAC(const unsigned char *str);
void freeDevTable();
void printDevStat();


// ----- ----- ANALYZING ----- ----- //
void Analyze(int caplen, const u_char *bytes) {
  printDevStat();

  // Gathering host info
  EthHeader* eth = (EthHeader*) bytes;
  unsigned char* hostMAC = eth->srcAddr;

  unsigned char* hostIP = NULL;
  if(eth->type == IP_PROTO) {
    IpHeader* ipFrame = (IpHeader*) (bytes + 14); // 14 Byte Ethernet header
    hostIP = ipFrame->srcIP;
  }

  DevStatics* device;
  unsigned long devID = hashMAC(hostMAC);
  HASH_FIND_INT(devicesTable, &devID, device);
  if(device == NULL){
    device = (DevStatics*) malloc(sizeof(DevStatics));

    device->pSend = 0;
    device->devID = devID;
    memcpy(device->hostMAC, hostMAC, 6);
    if(hostIP != NULL) memcpy(device->hostIP, hostIP, 4);

    HASH_ADD_INT(devicesTable, devID, device);  /* id: name of key field */
  }
  else {
    gTotPackets++;
    device->pSend = device->pSend + 1;
    if(hostIP != NULL) memcpy(device->hostIP, hostIP, 4);
  }
}


// ----- ----- CLEANING ----- ----- //
void printDevStat() {
  CLEAR_SCREEN;
  printf("Tot packets: %ld\n", gTotPackets);
  for(DevStatics* currentDev=devicesTable; currentDev != NULL; currentDev=currentDev->hh.next) {
    char devMac[18];
    stringFyMAC(devMac, currentDev->hostMAC);

    char devIP[18];
    stringFyIP(devIP, currentDev->hostIP);

    float perc = ((float) currentDev->pSend/gTotPackets);

    printf("Device:   MAC/%-18s   IP/%-17s   %%(%.4f)\n", devMac, devIP, perc);
  }
  fflush(stdout);
}

// ----- ----- CLEANING ----- ----- //
void freeDevTable() {
  struct DevStatics *currentDev, *tmp;

  HASH_ITER(hh, devicesTable, currentDev, tmp) {
    HASH_DEL(devicesTable, currentDev);
    free(currentDev);
  }
}


// ----- ----- HASHING ----- ----- //
unsigned long hashMAC(const unsigned char *str) {
  unsigned long hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;

  return hash;
}

#endif
