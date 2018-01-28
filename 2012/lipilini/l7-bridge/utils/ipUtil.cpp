#include <arpa/inet.h>
#include <string.h>

#include "ipUtil.h"

const char * proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

// IPv4 functions

int split_ipv4(splitted_ip_t * _sip, const char * ipv4){
	int a, b, c, d, m = 32;
  int e = 0;
  
  memset(_sip, 0, sizeof(splitted_ip_t));
  
	e = sscanf(ipv4, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &m);
  
  if(e < 4)
    return -1;
  
	_sip->ip.v4 = (a << 24) + (b << 16) + (c << 8) + d;
	
	if(m<1){
		m = 1;
	}
	else if(m>32){
		m = 32;
	}
	
	_sip->mask = m;
	
	return 0;
}

char * _intoa(unsigned int addr, char * buf, u_short bufLen) {
  // take from PF_RING example
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

char * intoa(unsigned int addr) {
  // take from PF_RING example
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}


// IPv6 functions

int split_ipv6(splitted_ip_t * _sip, const char * ipv6){
	char _ipv6[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	int m = 128;
  int e;
	
  memset(_sip, 0, sizeof(splitted_ip_t));
  
	e = sscanf(ipv6, "%s/%d", _ipv6, &m);
  
  if (e < 1){
    return -1;
  }
	
	e = inet_pton(AF_INET6, _ipv6, (void *)&(_sip->ip.v6));
  
  if( e <= 0){
    return -1;
  }
	
	if(m<1){
		m = 1;
	}
	else if(m>128){
		m = 128;
	}
	
	_sip->mask = m;
	
	return 0;
}

char * in6toa(struct in6_addr addr6) {
  // take from PF_RING example
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}
