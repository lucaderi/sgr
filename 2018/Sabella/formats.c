#include "formats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// ----- ----- ETHERNET FRAME ----- ----- //
int ETH_SIZE    = sizeof(EthHeader);
const unsigned char ETH_BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


// ----- ----- ARP MESSAGE FORMAT ----- ----- //
int ARP_REQUEST = (0x0001);
int ARP_REPLY   = (0x0002);
int ARP_SIZE    = sizeof(EthHeader) + sizeof(ArpMessage);


// ----- ----- IP HEADER ----- ----- //
int IP_PROTO = (0x0800);


// ----- ----- MISCELLANEOUS ----- ----- //
// For more info: djb2
unsigned long hashString(const unsigned char *str) {
  unsigned long hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;

  return hash;
}

// Ip to string function
void stringFyIP(char* target, const unsigned char aus[4]) {
  snprintf(target, 4, "%d.%d.%d.%d", aus[0], aus[1], aus[2], aus[3]);
}

// MAC to string function
void stringFyMAC(char* target, const unsigned char aus[6]) {
  snprintf(target, 6, "%02X:%02X:%02X:%02X:%02X:%02X", aus[0], aus[1], aus[2], aus[3], aus[4], aus[5]);
}

int stringToMAC(char* macString, unsigned char macHex[6]) {
  int values[6];
  if(6 == sscanf(macString, "%x:%x:%x:%x:%x:%x%*c",
    &values[0], &values[1], &values[2],
    &values[3], &values[4], &values[5]))
    {
    for(int i = 0; i < 6; ++i ) macHex[i] = (uint8_t) values[i];
    return 0;
  }
  else {
    fprintf(stderr, "Invalid MAC: %s\n", macString);
    return -1;
  }
}

int stringToIP(char* ipString, unsigned char ip[4]) {
  int values[4];
  if(4 == sscanf(ipString, "%d.%d.%d.%d%*c",
    &values[0], &values[1],
    &values[2], &values[3]))
    {
    for(int i = 0; i < 4; ++i ) ip[i] = (unsigned char) values[i];
    return 0;
  }
  else {
    fprintf(stderr, "Invalid IP: %s\n", ipString);
    return -1;
  }
}

uint8_t* BuildEthArp(int op, char* _srcIp, char* _srcMAC, char* _dstIp, char* _dstMAC) {
  uint8_t* bytes = (uint8_t*) malloc(ARP_SIZE);
  unsigned char srcIp [4]; stringToIP (_srcIp,  srcIp);
  unsigned char srcMAC[6]; stringToMAC(_srcMAC, srcMAC);
  unsigned char dstIp [4]; stringToIP (_dstIp,  dstIp);
  unsigned char dstMAC [6];
  if (op==ARP_REPLY) stringToMAC(_dstMAC, dstMAC);
  else memcpy(dstMAC, ETH_BROADCAST, 6);

  // Building standard Ethernet
  EthHeader* eth = (EthHeader*) bytes;
  eth->type = htons(0x0806);
  memcpy(eth->srcAddr, srcMAC, 6);
  memcpy(eth->dstAddr, dstMAC, 6);

  // Building standard ARP
  ArpMessage* arp = (ArpMessage*) (bytes + ETH_SIZE);
  arp->operation = op;
  arp->hwType = htons(0x0001); arp->hwLength = (6); // Ethernet
  arp->prType = htons(0x0800); arp->prLenght = (4); // IPv4
  memcpy(arp->srcPrAddr, srcIp, 4); memcpy(arp->srcHwAddr, srcMAC, 6);
  memcpy(arp->dstPrAddr, dstIp, 4); memcpy(arp->dstHwAddr, dstMAC, 6);

  return bytes;
}
