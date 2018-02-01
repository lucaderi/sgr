#ifndef FORMATS_H
#define FORMATS_H

// ----- ----- ETHERNET FRAME ----- ----- //
struct _EthHeader {
  unsigned char dstAddr[6]; // Source hardware address
  unsigned char srcAddr[6]; // Destination hardware address
  unsigned short type;
};
typedef struct _EthHeader EthHeader;
const unsigned char ETH_BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


// ----- ----- ARP MESSAGE FORMAT ----- ----- //
struct _ArpFormat {
  u_int16_t hwType;           // Hardware type
  u_int16_t prType;           // Protocol type
  unsigned char hwLength;     // Hardware length
  unsigned char prLenght;     // Protocol length
  u_int16_t operation;
  unsigned char srcHwAddr[6]; // Source hardware address
  unsigned char srcPrAddr[4]; // Source protocol address (assuming IPv4)
  unsigned char dstHwAddr[6]; // Destination hardware address
  unsigned char dstPrAddr[4]; // Source protocol address (assuming IPv4)
};
typedef struct _ArpFormat ArpFormat;

int ARP_REQUEST = (0x0001);
int ARP_REPLY   = (0x0002);
int ARP_SIZE    = sizeof(EthHeader) + sizeof(ArpFormat);


// ----- ----- IP HEADER ----- ----- //
struct _IpHeader {
  unsigned char garbage[12]; // Ayyyy pirate
  unsigned char srcIP[4];
  unsigned char dstIP[4];
};
typedef struct _IpHeader IpHeader;
int IP_PROTO = (0x0800);

// ----- ----- MISCELLANEOUS ----- ----- //
void stringFyIP(char* target, const unsigned char aus[4]) {
  sprintf(target, "%d.%d.%d.%d", aus[0], aus[1], aus[2], aus[3]);
}

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

void stringFyArp(char* targetString, ArpFormat* arpMsg) {
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

#endif
