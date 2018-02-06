#include "formats.h"

// ----- ----- ETHERNET FRAME ----- ----- //
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
  sprintf(target, "%d.%d.%d.%d", aus[0], aus[1], aus[2], aus[3]);
}

// MAC to string function
void stringFyMAC(char* target, const unsigned char aus[6]) {
  sprintf(target, "%02X:%02X:%02X:%02X:%02X:%02X", aus[0], aus[1], aus[2], aus[3], aus[4], aus[5]);
}

int stringToMAC(char* macString, unsigned char macHex[6]) {
  int i;
  char* token = strtok(macString, ":");
  for(i=0; i<6 && token; i++) {
    int hexDump;
    if(sscanf(token,"%02x", &hexDump) <= 0) return -1;
    macHex[i] = (unsigned char) hexDump;

    token = strtok(NULL, ":");
  }
  if(i != 6) return -1;

  return 0;
}

void stringToIP(char* ipString, unsigned char ip[4]) {
  struct sockaddr_in sa;

  inet_pton(AF_INET, ipString, &(sa.sin_addr));
  memcpy(ip, &(sa.sin_addr), 4);
}

// Ethernet frame to string
void stringFyEth(char* targetString, EthHeader* eth) {
  char srcMac[18]; stringFyMAC(srcMac, eth->srcAddr);
  char dstMac[18]; stringFyMAC(dstMac, eth->dstAddr);
  sprintf(targetString,
    "----- ----- ETH ----- -----\n"
    "source MAC: %s\n"
    "dst MAC:    %s\n"
    "----- ----- --- ----- ----- \n",
    srcMac, dstMac
  );
}

// ARP message to string
void stringFyArp(char* targetString, ArpMessage* arpMsg) {
  char* op = (arpMsg->operation == ARP_REQUEST) ? "Request" : "Reply";
  char srcIP[16];   stringFyIP (srcIP,  arpMsg->srcPrAddr);
  char srcMAC[18];  stringFyMAC(srcMAC, arpMsg->srcHwAddr);
  char dstIp[16];   stringFyIP (dstIp,  arpMsg->dstPrAddr);
  char dstMAC[18];  stringFyMAC(dstMAC, arpMsg->dstHwAddr);
  sprintf(targetString,
    "----- ----- ARP ----- -----\n"
    "op: %s\n"
    "source IP: %s\n"
    "dst IP:    %s\n"
    "source MAC: %s\n"
    "dst MAC:    %s\n"
    "----- ----- --- ----- ----- \n",
    op, srcIP, dstIp, srcMAC, dstMAC
  );
}
