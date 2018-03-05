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
  u_int16_t operation;        // Operation type
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
/*
 * NAME: hashString
 *
 * DESCRIPTION: hash a string with arbitrary length into a long
 *
 * INPUT:
 *        macIp - the string to be hashed
 *
 * RETURN: the hash value
 */
unsigned long hashString(const unsigned char *str);

/*
 * NAME: stringFyIP
 *
 * DESCRIPTION: convert an IP address to a string
 *
 * INPUT:
 *        aus    - the array containing the IP address
 *        target - the string in which the address will be copied
 */
void stringFyIP(char* target, const unsigned char aus[4]);

/*
 * NAME: stringFyMAC
 *
 * DESCRIPTION: convert a MAC address to a string
 *
 * INPUT:
 *        aus    - the array containing the MAC address
 *        target - the string in which the address will be copied
 */
void stringFyMAC(char* target, const unsigned char aus[6]);

/*
 * NAME: stringToMAC
 *
 * DESCRIPTION: convert a string containing a MAC address with the standard format
 *              to a MAC address
 *
 * INPUT:
 *        macHex    - the char array in which the address will be copied
 *        macString - the string containing the MAC address
 *
 * RETURN: zero on success; -1 if an error occurres
 */
int stringToMAC(char* macString, unsigned char macHex[6]);

/*
 * NAME: stringToIP
 *
 * DESCRIPTION: convert a string containing an IP address with the standard format
 *              to an IP address
 *
 * INPUT:
 *        macHex    - the char array in which the address will be copied
 *        macString - the string containing the IP address
 *
 * RETURN: zero on success; -1 if an error occurres
 */
int stringToIP(char* ipString, unsigned char ip[4]);

/*
 * NAME: BuildEthArp
 *
 * DESCRIPTION: builds an arp packet (assuming Ethernet + IPv4)
 *
 * INPUT:
 *        op     - request or reply
 *        srcIP  - source IP address
 *        srcMAC - source MAC address
 *        dstIP  - destination IP address
 *        dstMAC - destination MAC address, NULL on requests
 *
 * RETURN: tha packet to be send
 */
uint8_t* BuildEthArp(int op, char* srcIP, char* srcMAC, char* dstIP, char* dstMAC);

#endif
