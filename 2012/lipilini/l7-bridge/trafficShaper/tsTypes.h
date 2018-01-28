#ifndef _TSTYPES_H_
#define _TSTYPES_H_

#include <pthread.h>

#include "globalTypes.h"

typedef struct queue{
  recv_pkt_t ** data;
  pthread_mutex_t m;
  u_int32_t size;
  u_int32_t head;
  u_int32_t tail;
}queue_t;

typedef struct masterQueue{
  queue_t queue;
  u_int32_t weight;
  u_int32_t token;
  u_int64_t lastVisitTick;
}masterQueue_t;

#endif // _TSTYPES_H_