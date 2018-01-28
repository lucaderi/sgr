#ifndef _FLOWUTIL_H
#define _FLOWUTIL_H

#include "flowTypes.h"

void build_flow_key(u_int8_t _ip_version, u_int8_t _ip_proto, ip_addr * _src_ip, u_int16_t _src_port, ip_addr * _dst_ip, u_int16_t _dst_port, flowKey_t * key, bool * upper_is_src);

void print_flow_key(flowKey_t * _key, bool _upper_is_src);
void print_flow_info(flowInfo_t * _info, bool _upper_is_src, timeval * _now);

#endif // _FLOWUTIL_H