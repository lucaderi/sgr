#ifndef _FLOWTYPES_H_
#define	_FLOWTYPES_H_

#include <ctime>
#include "pfring.h"

extern "C" {
  #include "ipq_api.h"
  #include "ipq_structs.h"
}

#include "ruleNode.h"

typedef struct flowKey{
  u_int8_t  ip_version;
  u_int8_t  ip_proto;
  ip_addr lower_ip;
  u_int16_t lower_port;
  ip_addr upper_ip;
  u_int16_t upper_port;
}flowKey_t;

typedef struct flowInfo{
  u_int32_t l7_proto;
  u_int32_t upper_n_pkt;
  u_int64_t upper_n_bytes;
  timeval upper_last_pkt_time;
  u_int32_t lower_n_pkt;
  u_int64_t lower_n_bytes;
  timeval lower_last_pkt_time;
  bool is_upper_last_pkt;
}flowInfo_t;

typedef struct rule_info{
	u_int32_t version;
	rule_ret_t rule;
}rule_info_t;

typedef struct nDPI_info{
  struct ipoque_flow_struct flow;
  struct ipoque_id_struct src;
  struct ipoque_id_struct dst;
}nDPI_info_t;

#endif	// _FLOWTYPES_H_

