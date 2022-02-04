#ifndef _FLOWSTRUCT_H_
#define _FLOWSTRUCT_H_

#include "flowTypes.h"
#include "pfring.h"

class flowStruct
{
    public:
        flowStruct(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts);
        ~flowStruct();
        void reset_struct(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts);
        __inline__ ip_addr * get_src_ip() { return ( (upper_is_src) ? &(key.upper_ip) : &(key.lower_ip) ); }
        __inline__ ip_addr * get_dst_ip() { return ( (upper_is_src) ? &(key.lower_ip) : &(key.upper_ip) ); }
        __inline__ bool have_same_key(flowKey_t * _key) { return ( memcmp(&key, _key, sizeof(flowKey_t)) == 0); }
        __inline__ u_int32_t get_l7_proto() { return info.l7_proto; }
        __inline__ void set_l7_proto(u_int32_t _l7_proto) { info.l7_proto = _l7_proto; }
        __inline__ void update_upper_info(u_int64_t _n_bytes, timeval * _pkt_ts)
            { info.upper_n_bytes += _n_bytes; info.upper_n_pkt++; info.upper_last_pkt_time = *_pkt_ts; info.is_upper_last_pkt = true; }
        __inline__ void update_lower_info(u_int64_t _n_bytes, timeval * _pkt_ts)
            { info.lower_n_bytes += _n_bytes; info.lower_n_pkt++; info.lower_last_pkt_time = *_pkt_ts; info.is_upper_last_pkt = false; }
        __inline__ u_int32_t get_src_n_pkt() { return ( (upper_is_src) ? info.upper_n_pkt : info.lower_n_pkt ); }
        __inline__ u_int32_t get_dst_n_pkt() { return ( (upper_is_src) ? info.lower_n_pkt : info.upper_n_pkt ); }
        __inline__ u_int64_t get_src_n_bytes() { return ( (upper_is_src) ? info.upper_n_bytes : info.lower_n_bytes ); }
        __inline__ u_int64_t get_dst_n_bytes() { return ( (upper_is_src) ? info.lower_n_bytes : info.upper_n_bytes ); }
        __inline__ timeval * get_last_pkt_time() { return ( (info.is_upper_last_pkt) ? &(info.upper_last_pkt_time) : &(info.lower_last_pkt_time) ); }
        __inline__ u_int32_t get_flow_rule_version() { return flow_rule_info.version; }
        __inline__ rule_ret_t get_flow_rule() { return flow_rule_info.rule; }
        __inline__ void set_flow_rule(rule_ret_t * _rR, u_int32_t _vers) { flow_rule_info.version = _vers; flow_rule_info.rule = *_rR; }
        __inline__ struct ipoque_flow_struct * get_addr_of_nDPI_flow() { return &(detection_info.flow); }
        __inline__ struct ipoque_id_struct * get_addr_of_nDPI_src() { return &(detection_info.src); }
        __inline__ struct ipoque_id_struct * get_addr_of_nDPI_dst() { return &(detection_info.dst); }
        __inline__ flowStruct * get_next() { return next; }
        __inline__ void set_next(flowStruct * _next) { next = _next; }
        void print_flow_struct(timeval * tv);
        
    protected:

    private:
        flowKey_t key;
        bool upper_is_src;
        flowInfo_t info;
        rule_info_t flow_rule_info;
        nDPI_info_t detection_info;

        flowStruct * next;
};

#endif // _FLOWSTRUCT_H_
