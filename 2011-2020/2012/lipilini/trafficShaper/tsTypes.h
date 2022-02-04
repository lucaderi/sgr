/*
 * tsTypes.h
 * Typedef for trafficShaper
 * 
 * Jacopo Lipilini
 * 
 */

#include <pthread.h>

#include "pfring.h"

typedef struct packet{
  pfring * ring;
  u_char * pkt;
  u_int len;
}packet_t;

#define NULL_PACKET { NULL, NULL, 0 }

typedef struct slaveQueue{
  packet_t * queue;
  pthread_mutex_t m;
  u_int16_t head;
  u_int16_t tail;
}slaveQueue_t;

typedef struct masterQueue{
  slaveQueue_t * sQueue;
  u_int32_t weight;
  u_int32_t token;
  u_int16_t lastSlaveQueue;
  u_int64_t lastVisitTick;
}masterQueue_t;

typedef struct trafficShaper{
  masterQueue_t * mQueue;
  u_int16_t masterQueueNumber;
  u_int16_t slaveQueueNumber;
  u_int16_t queueSize;
  u_int16_t lastMasterQueue;
  u_int64_t cpuFreq;
}trafficShaper_t;
