#include <cstdio>
#include <cstring>

#include "flowUtil.h"

#include "ipUtil.h"

void build_flow_key(u_int8_t _ip_version, u_int8_t _ip_proto, ip_addr * _src_ip, u_int16_t _src_port, ip_addr * _dst_ip, u_int16_t _dst_port, flowKey_t * key, bool * upper_is_src){
  memset(key, 0, sizeof(flowKey_t));
  
  key->ip_version = _ip_version;
  key->ip_proto = _ip_proto;
  
  if(_ip_version == 4){
    if(is_greater_ipv4(_src_ip->v4, _dst_ip->v4)){
      key->upper_ip = *_src_ip;
      key->upper_port = _src_port;
      key->lower_ip = *_dst_ip;
      key->lower_port = _dst_port;
      *upper_is_src = true;
    }else{
      key->upper_ip = *_dst_ip;
      key->upper_port = _dst_port;
      key->lower_ip = *_src_ip;
      key->lower_port = _src_port;
      *upper_is_src = false;
    }
  }
  else if(_ip_version == 6){
    if(is_greater_ipv6(_src_ip->v6, _dst_ip->v6)){
      key->upper_ip = *_src_ip;
      key->upper_port = _src_port;
      key->lower_ip = *_dst_ip;
      key->lower_port = _dst_port;
      *upper_is_src = true;
    }else{
      key->upper_ip = *_dst_ip;
      key->upper_port = _dst_port;
      key->lower_ip = *_src_ip;
      key->lower_port = _src_port;
      *upper_is_src = false;
    }
  }
  else{
    // should never here !
    return;
  }
}

void print_flow_key(flowKey_t * _key, bool _upper_is_src){
  printf("IP_VERS %i , IP_PROTO %i (%s)\n", _key->ip_version, _key->ip_proto, proto2str(_key->ip_proto));
  
  if(_key->ip_version == 4){  
    printf("SRC IP:PORT %s:%i\n", (_upper_is_src) ? intoa(_key->upper_ip.v4) : intoa(_key->lower_ip.v4),
            (_upper_is_src) ? _key->upper_port : _key->lower_port);
    printf("DST IP:PORT %s:%i\n", (_upper_is_src) ? intoa(_key->lower_ip.v4) : intoa(_key->upper_ip.v4),
            (_upper_is_src) ? _key->lower_port : _key->upper_port);
  }
  else if(_key->ip_version == 6){
    printf("SRC IP:PORT %s:%i\n", (_upper_is_src) ? in6toa(_key->upper_ip.v6) : in6toa(_key->lower_ip.v6),
            (_upper_is_src) ? _key->upper_port : _key->lower_port);
    printf("DST IP:PORT %s:%i\n", (_upper_is_src) ? in6toa(_key->lower_ip.v6) : in6toa(_key->upper_ip.v6),
            (_upper_is_src) ? _key->lower_port : _key->upper_port);
	}
	else{
		printf("No IP flow !\n");
	}
}

void print_flow_info(flowInfo_t * _info, bool _upper_is_src, timeval * _now){
  printf("L7_PROTO %i\n", _info->l7_proto);
  printf("N_SRC_PKT %u - N_SRC_BYTES %lu\n", (_upper_is_src) ? _info->upper_n_pkt : _info->lower_n_pkt,
          (_upper_is_src) ? _info->upper_n_bytes : _info->lower_n_bytes);
  printf("N_DST_PKT %u - N_DST_BYTES %lu\n", (_upper_is_src) ? _info->lower_n_pkt : _info->upper_n_pkt,
          (_upper_is_src) ? _info->lower_n_bytes : _info->upper_n_bytes);
  printf("LAST_PKT %li sec . %li usec ago", _now->tv_sec - ((_upper_is_src) ? _info->upper_last_pkt_time.tv_sec : _info->lower_last_pkt_time.tv_sec),
          _now->tv_usec - ((_upper_is_src) ? _info->upper_last_pkt_time.tv_usec : _info->lower_last_pkt_time.tv_usec));

}