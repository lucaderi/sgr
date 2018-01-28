#ifndef _GLOBALTYPES_H_
#define _GLOBALTYPES_H_

#include "pfring.h"

#define DEFAULT_SNAPLEN 1560

typedef struct recv_pkt{
  // util info
  int32_t _rx_if_index;
  u_int32_t _caplen;
  int16_t _l3_offset;
  timeval _pkt_ts;
  
  // flow info
  u_int8_t _ip_version;
  u_int8_t _ip_proto;
  ip_addr _src_ip;
  u_int16_t _src_port;
  ip_addr _dst_ip;
  u_int16_t _dst_port;
  
  // other info
  u_int64_t _n_bytes;
  
  // real packet
  u_char p[DEFAULT_SNAPLEN];
  
  // flag
  int in_use;
}recv_pkt_t;

#endif // _GLOBALTYPES_H_