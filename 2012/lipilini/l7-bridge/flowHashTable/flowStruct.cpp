#include <cstdio>

#include "flowStruct.h"

#include "flowUtil.h"
#include "ipUtil.h"

flowStruct::flowStruct(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts){
  key = *_key;
  
  upper_is_src = _upper_is_src;
  
  memset(&info, 0, sizeof(flowInfo_t));
  info.l7_proto = IPOQUE_PROTOCOL_UNKNOWN;
  if(upper_is_src){
    info.upper_n_bytes = _n_bytes;
    info.upper_n_pkt = 1;
    info.upper_last_pkt_time = *_pkt_ts;
    info.is_upper_last_pkt = true;
  }else{
    info.lower_n_bytes = _n_bytes;
    info.lower_n_pkt = 1;
    info.lower_last_pkt_time = *_pkt_ts;
    info.is_upper_last_pkt = false;
  }
  
  memset(&flow_rule_info, 0, sizeof(rule_info_t));
  
  memset(&detection_info, 0, sizeof(nDPI_info_t));
}

flowStruct::~flowStruct(){
  //delete this;
}

void flowStruct::reset_struct(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts){
  key = *_key;
  
  upper_is_src = _upper_is_src;
  
  memset(&info, 0, sizeof(flowInfo_t));
  info.l7_proto = IPOQUE_PROTOCOL_UNKNOWN;
  if(upper_is_src){
    info.upper_n_bytes = _n_bytes;
    info.upper_n_pkt = 1;
    info.upper_last_pkt_time = *_pkt_ts;
    info.is_upper_last_pkt = true;
  }else{
    info.lower_n_bytes = _n_bytes;
    info.lower_n_pkt = 1;
    info.lower_last_pkt_time = *_pkt_ts;
    info.is_upper_last_pkt = false;
  }
  
  memset(&flow_rule_info, 0, sizeof(rule_info_t));
  
  memset(&detection_info, 0, sizeof(nDPI_info_t));
}

void flowStruct::print_flow_struct(timeval * tv){
  print_flow_key(&key, upper_is_src);
  
  printf("\t----------\n");
  
  print_flow_info(&info, upper_is_src, tv);
}
