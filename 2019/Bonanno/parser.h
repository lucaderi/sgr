#ifndef GDR19_PARSER_H
#define GDR19_PARSER_H

#include <sys/param.h>

//Offset of the first byte of the "Ethertype" Ethernet header field
#define ETH_PROT_BYTE1 12
#define ETH_HEAD_SIZE 14

//Ethertype field values
#define ETH_IPV4 0x0800

//Offset of the "Protocol" IPv4 header field
#define IP_PROT_BYTE 23
#define IP_PROT_TCP 0x06
#define IP_PROT_UDP 0x11
#define IP_PROT_ICMP 0x01

//Offset of the "Internet Header Length" IPv4 header field
#define IHL_BYTE 14
#define IHL_BYTE_MASK 0xF

//Offset of the first byte of the "Total Length" IPv4 header field
#define IP4_TOTLENGTH_OFFST 16

//Offset of the first byte of the "Source Address" IPv4 header field
#define IP4_SRCADDR_OFFST 26

//Offset of the first byte of the "Destination Address" IPv4 header field
#define IP4_DESTADDR_OFFST 30
//Offset of the first byte of the "Legnth" UDP header field, relative to the UDP header
#define UDP_LENGTH_OFFST 8
#define UDP_HEADER_SIZE 8
//Offset of the first byte of the "Offset" TCP header field, relative to the TCP header
#define TCP_OFFSET_OFFST 12
#define TCP_OFFSET_MASK 0xF0

//ICMP message types (RFC792) and the relative message lengths, minus the first 4 bytes common to all message types (Type/Code/Chechsum field)
#define ICMP_TYPE_DESTUNRCH 3
#define ICMP_TYPE_TIMEEXCD 11
#define ICMP_TYPE_PARAMPM 12
#define ICMP_TYPE_SRCQNCMSG 4
#define ICMP_TYPE_REDIRM 5
#define ICMP_TYPE_ECHOMSG 8
#define ICMP_TYPE_ECHORPLY 0
#define ICMP_TYPE_TIMESTMP 13
#define ICMP_TYPE_TIMESTMPRPLY 14
#define ICMP_TYPE_INFOREQ 15
#define ICMP_TYPE_INFORLY 16

u_int twobytecnc(u_char a, u_char b);

u_int fourbytecnc(u_char a, u_char b, u_char c, u_char d);

u_int get_eth_type(const u_char *packet);

u_int get_ip4_prot(const u_char *packet);

u_int get_ip4_ihl(const u_char *packet);

u_int get_ip4_totlength(const u_char *packet);

u_int get_udp_payload(const u_char *packet);

u_int get_tcp_payload(const u_char *packet);

u_int get_icmp_payload(const u_char *packet);

u_int get_ip4_srcaddr(const u_char *packet);

u_int get_ip4_destaddr(const u_char *packet);

#endif //GDR19_PARSER_H
