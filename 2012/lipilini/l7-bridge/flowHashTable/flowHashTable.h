#ifndef _FLOWHASHTABLE_H_
#define _FLOWHASHTABLE_H_

#include "pfring.h"
#include "flowList.h"
#include "ipUtil.h"

class flowHashTable
{
    public:
        flowHashTable(u_int32_t _size);
        ~flowHashTable();
        flowStruct * add_new_capt_pkt(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts, timeval * _now);
        u_int32_t periodic_remove_deletable_flow(timeval * _now);
        __inline__ u_int32_t get_flowNum() { return flowNum; }
        void print_flow_hash_table();
        
    protected:
        __inline__ u_int32_t hash4(flowKey_t * _key)
            { return (u_int32_t) ((_key->ip_version + _key->ip_proto + _key->lower_ip.v4 + _key->lower_port + _key->upper_ip.v4 + _key->upper_port) & sizeMask); }
        
        __inline__ u_int32_t hash6(flowKey_t * _key)
            { return (u_int32_t) ((_key->ip_version + _key->ip_proto + sum_ipv6(_key->lower_ip.v6) + _key->lower_port + sum_ipv6(_key->upper_ip.v6) + _key->upper_port) & sizeMask); }
    
    private:
        flowList ** table;
        u_int32_t size;
        u_int32_t sizeMask;
        u_int32_t flowNum;
        u_int32_t maxFlowNum;
        u_int32_t limFlowNum;
        u_int32_t listToUpdate;
        u_int32_t listUpdateLim;
};

#endif // _FLOWHASHTABLE_H_
