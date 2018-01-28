#ifndef _FLOWLIST_H_
#define _FLOWLIST_H_

#include "flowStruct.h"
#include "pfring.h"

class flowList
{
    public:
        flowList();
        ~flowList();
        flowStruct * find_list_flow(flowKey_t * _key, timeval * _now);
        __inline__ bool have_unused_flow() { return (firstUnusedFlowPointer != NULL); }
        flowStruct * pick_from_unused_flow();
        
        __inline__ flowStruct * add_new_list_flow(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts)
            { flowStruct * _pFS = new flowStruct(_key, _upper_is_src, _n_bytes, _pkt_ts); move_on_top(_pFS); return _pFS; }
        
        __inline__ flowStruct * reuse_list_flow(flowStruct * _pFS, flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts)
            { _pFS->reset_struct(_key, _upper_is_src, _n_bytes, _pkt_ts); move_on_top(_pFS); return _pFS; }
        
        __inline__ flowStruct * update_list_flow(flowStruct * _pFS, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts)
            { (_upper_is_src) ? _pFS->update_upper_info(_n_bytes, _pkt_ts) : _pFS->update_lower_info(_n_bytes, _pkt_ts); move_on_top(_pFS); return _pFS; }
        
        u_int32_t remove_deletable_list_flow();
        void print_flow_list(timeval * _now);
        
    protected:
        __inline__ void detach_from_head(flowStruct * detaching) { activeFlowHead = detaching->get_next(); }
        __inline__ void detach_from_list(flowStruct * prev, flowStruct * detaching) { prev->set_next(detaching->get_next()); }
        __inline__ void move_on_top(flowStruct * p) { p->set_next(activeFlowHead); activeFlowHead = p; }
				
    private:
        // list of active flows
        flowStruct * activeFlowHead;
        // last active flow
        flowStruct * lastActiveFlowPointer;
        // first idle flow
        flowStruct * firstUnusedFlowPointer;
};

#endif // _FLOWLIST_H_
