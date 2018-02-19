#ifndef FORMATS_H
#define FORMATS_H

#include <arpa/inet.h>

// ----- ----- ETHERNET FRAME ----- ----- //
typedef struct _EthHeader {
  unsigned char dstAddr[6]; // Source hardware address
  unsigned char srcAddr[6]; // Destination hardware address
  unsigned short type;
} EthHeader;
extern const unsigned char ETH_BROADCAST[6];


// ----- ----- ARP MESSAGE FORMAT ----- ----- //
typedef struct _ArpMessage {
  u_int16_t hwType;           // Hardware type
  u_int16_t prType;           // Protocol type
  unsigned char hwLength;     // Hardware length
  unsigned char prLenght;     // Protocol length
  u_int16_t operation;
  unsigned char srcHwAddr[6]; // Source hardware address
  unsigned char srcPrAddr[4]; // Source protocol address (assuming IPv4)
  unsigned char dstHwAddr[6]; // Destination hardware address
  unsigned char dstPrAddr[4]; // Source protocol address (assuming IPv4)
} ArpMessage;

extern int ARP_REQUEST;
extern int ARP_REPLY;
extern int ARP_SIZE;


// ----- ----- IP HEADER ----- ----- //
typedef struct _IpHeader {
  unsigned char garbage[12]; // Ayyyy pirate
  unsigned char srcIP[4];
  unsigned char dstIP[4];
} IpHeader;
extern int IP_PROTO;


// ----- ----- MISCELLANEOUS ----- ----- //
unsigned long hashString(const unsigned char *str);

// Ip to string function
void stringFyIP(char* target, const unsigned char aus[4]);

// MAC to string function
void stringFyMAC(char* target, const unsigned char aus[6]);

int stringToMAC(char* macString, unsigned char macHex[6]);

int stringToIP(char* ipString, unsigned char ip[4]);

uint8_t* BuildEthArp(int op, char* srcIP, char* srcMAC, char* dstIp, char* dstMAC);

#endif
