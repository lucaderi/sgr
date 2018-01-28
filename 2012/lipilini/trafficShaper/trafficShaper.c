/*
 * trafficShaper.c
 * Deficit Weighted Round Robin implementation of trafficShaper
 * 
 * Jacopo Lipilini
 * 
 */

#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "trafficShaper.h"

#define DEFAULT_TIME_TO_WAIT { 0, 1000 }

typedef u_int64_t ticks;

static __inline__ ticks getticks(void){
  u_int32_t a, d;
  /* asm("cpuid"); // serialization */
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));
}

trafficShaper_t * init_traffic_shaper(u_int16_t no_mq, u_int16_t w[], u_int16_t no_sq, u_int16_t qs){
  int i, j;
  ticks tick_start, tick_delta;
  
  trafficShaper_t * ts = NULL;
  
  /* initializing traffic shaper struct */
  ts = (trafficShaper_t *)calloc(1, sizeof(trafficShaper_t));
  if(ts == NULL)
    return NULL;
  
  ts->masterQueueNumber = no_mq;
  ts->slaveQueueNumber = no_sq;
  ts->queueSize = qs;
  
  ts->lastMasterQueue = 0;
  
  /* computing CPU frequence (code take from PF_RING example pfsend.c) */
  tick_start = getticks();
  usleep(1);
  tick_delta = getticks() - tick_start;

  tick_start = getticks();
  usleep(1001);
  ts->cpuFreq = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
  
  ts->mQueue = (masterQueue_t *)calloc(no_mq, sizeof(masterQueue_t));
  if(ts->mQueue == NULL)
    return NULL;
  
  /* initializing master queues */
  for(i=0; i<no_mq; i++){
    ts->mQueue[i].weight = w[i];
    ts->mQueue[i].token = 0;
    ts->mQueue[i].lastSlaveQueue = 0;
    ts->mQueue[i].lastVisitTick = 0;
    
    ts->mQueue[i].sQueue = (slaveQueue_t *)calloc(no_sq, sizeof(slaveQueue_t));
    if(ts->mQueue[i].sQueue == NULL)
      return NULL;
    
    /* initializing slave queues */
    for(j=0; j<no_sq; j++){
      ts->mQueue[i].sQueue[j].queue = (packet_t *)calloc(qs, sizeof(packet_t));
      if(ts->mQueue[i].sQueue[j].queue == NULL)
        return NULL;
      
      if(pthread_mutex_init(&(ts->mQueue[i].sQueue[j].m), NULL) != 0)
        return NULL;
      ts->mQueue[i].sQueue[j].head = 0;
      ts->mQueue[i].sQueue[j].tail = 0;
    }
  }
  
  return ts;
}

void term_traffic_shaper(trafficShaper_t * ts){
  int i, j;
  
  for(i=0; i<ts->masterQueueNumber; i++){
    for(j=0; j<ts->slaveQueueNumber; j++){
      free(ts->mQueue[i].sQueue[j].queue);
    }
    free(ts->mQueue[i].sQueue);
  }
  
  free(ts->mQueue);
  
  free(ts);
  
  return;
}

int enqueue_packet(trafficShaper_t * ts, u_int16_t mq, u_int16_t sq, packet_t p){
  slaveQueue_t * pSQ = NULL; /* pointer to Slave Queue selected */
  
  if(ts == NULL || mq >= ts->masterQueueNumber || sq >= ts->slaveQueueNumber)
    return -1;
  
  pSQ = &(ts->mQueue[mq].sQueue[sq]);
  
  pthread_mutex_lock(&(pSQ->m));
  
  /* check if the queue is full */
  if( (pSQ->head==0 && pSQ->tail==(ts->queueSize-1)) || (pSQ->head==(pSQ->tail+1)) ){
    pthread_mutex_unlock(&(pSQ->m));
    return -1;
  }
  
  /* enqueue packet in free slot */
  pSQ->queue[pSQ->tail] = p;
  
  /* update tail */
  pSQ->tail++;
  if(pSQ->tail == ts->queueSize)
    pSQ->tail = 0;
  
  pthread_mutex_unlock(&(pSQ->m));
  
  return 0;
}

packet_t dequeue_packet(trafficShaper_t * ts, u_int wait){
  int j;
  
  slaveQueue_t * pSQ = NULL;
  masterQueue_t * pMQ = NULL;
  packet_t p = NULL_PACKET;
  ticks t, t_delta;
  u_int32_t credit;
  u_int16_t firstMasterQueue;
  static const struct timespec wait_ts = DEFAULT_TIME_TO_WAIT;
  
  if(ts == NULL)
    return p;
  
  firstMasterQueue = ts->lastMasterQueue;
  
  while(1){
    pMQ = &(ts->mQueue[ts->lastMasterQueue]);
    
    /* update master queue status */
    t = getticks();
    t_delta = t - pMQ->lastVisitTick;
    
    pMQ->lastVisitTick = t;
    
    credit = (u_int32_t) ((double) pMQ->weight * ((double) t_delta / ts->cpuFreq));
    
    pMQ->token += credit;
    if(pMQ->token > pMQ->weight)
      pMQ->token = pMQ->weight;
    
    /* search in slave queues for a packet */
    for(j=0; j<ts->slaveQueueNumber; j++){
      pSQ = &(pMQ->sQueue[pMQ->lastSlaveQueue]);
      
      pthread_mutex_lock(&(pSQ->m));
      
      /* check if queue is empty or if token aren't enough to send packet */
      if(pSQ->head == pSQ->tail || pMQ->token < pSQ->queue[pSQ->head].len){
        pthread_mutex_unlock(&(pSQ->m));
        
        pMQ->lastSlaveQueue++;
        if(pMQ->lastSlaveQueue == ts->slaveQueueNumber)
          pMQ->lastSlaveQueue = 0;
        
      }else{
        /* here if the queue have a sendable packet */
        p = pSQ->queue[pSQ->head];

        pSQ->head++;
        if(pSQ->head == ts->queueSize)
          pSQ->head = 0;

        pthread_mutex_unlock(&(pSQ->m));

        pMQ->token -= p.len;

        pMQ->lastSlaveQueue++;
        if(pMQ->lastSlaveQueue == ts->slaveQueueNumber)
          pMQ->lastSlaveQueue = 0;

        ts->lastMasterQueue++;
        if(ts->lastMasterQueue == ts->masterQueueNumber)
          ts->lastMasterQueue = 0;

        return p;
      }
    }
    
    /* here if any sendable packet in slave queues is found */
    ts->lastMasterQueue++;
    if(ts->lastMasterQueue == ts->masterQueueNumber)
      ts->lastMasterQueue = 0;
    
    /* check if searched all master queues */
    if(ts->lastMasterQueue == firstMasterQueue){
      if(wait){
        nanosleep(&wait_ts, NULL);
      }else{
        break;
      }
    }
  }
  
  /* here if no sendable packet is found and haven't to wait */
  return p;
}

u_int32_t send_shaped_traffic(trafficShaper_t * ts, u_int32_t n_pkt, u_int wait){
  int e = 0;
  
  u_int32_t sent_pkt = 0;
  packet_t p = NULL_PACKET;
  
  if(ts == NULL)
    return 0;
  
  while(1){
    p = dequeue_packet(ts, wait);

    e = pfring_send(p.ring, (char *)p.pkt, p.len, 1);
    if(e < 0){
      return sent_pkt;
    }else{
      sent_pkt++;
    }
    
    if(n_pkt != 0 && sent_pkt == n_pkt){
      break;
    }
  }
  
  return sent_pkt;
}