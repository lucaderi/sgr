#ifndef _IPUTIL_H
#define _IPUTIL_H

#include <stdio.h>
#include <netinet/in.h>

#include "pfring.h"

typedef struct splitted_ip{
	ip_addr ip;
	int mask;
}splitted_ip_t;

static __inline__ bool is_set_bit(int num, int bit){
	return ((num & (1 << bit)) != 0);
}

const char * proto2str(u_short proto);

// IPv4 functions
int split_ipv4(splitted_ip_t * _sip, const char * ipv4);

static __inline__ bool equal_ipv4(u_int32_t ip1, u_int32_t ip2){
  return (ip1 == ip2);
}

static __inline__ bool is_greater_ipv4(u_int32_t ip1, u_int32_t ip2){
  return (ip1 > ip2);
}

char * intoa(unsigned int addr);

// IPv6 functions
int split_ipv6(splitted_ip_t * _sip, const char * ipv6);

static __inline__ bool equal_ipv6(struct in6_addr ip1, struct in6_addr ip2){
  return ((ip1.__in6_u.__u6_addr32[0] == ip2.__in6_u.__u6_addr32[0]) && (ip1.__in6_u.__u6_addr32[1] == ip2.__in6_u.__u6_addr32[1])
          && (ip1.__in6_u.__u6_addr32[2] == ip2.__in6_u.__u6_addr32[2]) && (ip1.__in6_u.__u6_addr32[3] == ip2.__in6_u.__u6_addr32[3]));
}

static __inline__ bool is_greater_ipv6(struct in6_addr ip1, struct in6_addr ip2){
  return ((ip1.__in6_u.__u6_addr32[0] > ip2.__in6_u.__u6_addr32[0]) ||
          (ip1.__in6_u.__u6_addr32[0] == ip2.__in6_u.__u6_addr32[0] && ip1.__in6_u.__u6_addr32[1] > ip2.__in6_u.__u6_addr32[1]) ||
          (ip1.__in6_u.__u6_addr32[0] == ip2.__in6_u.__u6_addr32[0] && ip1.__in6_u.__u6_addr32[1] == ip2.__in6_u.__u6_addr32[1] && ip1.__in6_u.__u6_addr32[2] > ip2.__in6_u.__u6_addr32[2]) ||
          (ip1.__in6_u.__u6_addr32[0] == ip2.__in6_u.__u6_addr32[0] && ip1.__in6_u.__u6_addr32[1] == ip2.__in6_u.__u6_addr32[1] && ip1.__in6_u.__u6_addr32[2] == ip2.__in6_u.__u6_addr32[2] && ip1.__in6_u.__u6_addr32[3] > ip2.__in6_u.__u6_addr32[3]));
}

static __inline__ u_int32_t sum_ipv6(struct in6_addr _addr){
  return (_addr.__in6_u.__u6_addr32[0] + _addr.__in6_u.__u6_addr32[1]
          + _addr.__in6_u.__u6_addr32[2] + _addr.__in6_u.__u6_addr32[3]);
}

char * in6toa(struct in6_addr addr6);

#endif // _IPUTIL_H
