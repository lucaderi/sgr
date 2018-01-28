#ifndef _TRAFFICSHAPER_H_
#define _TRAFFICSHAPER_H_

#include "tsTypes.h"

class trafficShaper
{
  public:
    trafficShaper(char * _conf_file);
    ~trafficShaper();
    int init_traffic_shaper();
    bool enqueue_packet(u_int16_t _mq, recv_pkt_t * _pRP);
    recv_pkt_t * dequeue_packet();
    
  protected:
    __inline__ u_int32_t idx_incr(u_int32_t _idx) { return( (_idx == queueSizeLim) ? 0 : _idx + 1 ); }
    __inline__ void mQueue_incr() { if(lastMasterQueue == masterQueueNumberLim){ lastMasterQueue = 0; }else{ lastMasterQueue++; } }
    __inline__ bool isEmpty(queue_t * _q) { return ( _q->data[_q->head] == NULL ); }
    __inline__ bool isFull(queue_t * _q) { return ( _q->data[_q->tail] != NULL ); }
    
  private:
    char * conf_file;
    masterQueue_t * mQueue;
    u_int16_t masterQueueNumber;
    u_int16_t masterQueueNumberLim;
    u_int16_t lastMasterQueue;
    u_int32_t queueSize;
    u_int32_t queueSizeLim;
    u_int64_t cpuFreq;
};

#endif // _TRAFFICSHAPER_H_