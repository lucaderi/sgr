#ifndef __FLOW_H__
#define __FLOW_H__

#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pthread.h>

/* 2^FLOW_HASH_TAB_SIZE */
#define FLOW_HASH_TAB_SIZE 3

#define FLOW_BUF_NO 4

#define FLOW_BUF_SIZE 100

#define FREE_LIST_SIZE 8192
#define FLOW_COLLECTOR_INTERVAL 20
#define FLOW_MAX_TIME 1800
#define FLOW_EXPIRE_TIME 15


typedef u_int hash_t;

typedef struct pkt_decoded{
  hash_t hash;
  struct in_addr src;
  struct in_addr dst;
  u_short size;
  int s_port;
  int d_port;
  u_char proto;
  struct timeval time;
  //test
  int inOut;
} pkt_rec_t;

typedef struct flow_buffer{
  sig_atomic_t first;
  sig_atomic_t last;
  int size;
  pkt_rec_t buf[FLOW_BUF_SIZE];
}flow_buffer_t;

typedef struct flow{
  struct flow *next;
  struct timeval l_time;
  struct timeval s_time;
  struct in_addr addr_dir1, addr_dir2;
  u_short port_dir1, port_dir2;
  u_char proto;
  u_long b_dir1, npkt_dir1;
  u_long b_dir2, npkt_dir2;
}flow_t;

typedef struct flow_info{
  flow_t *flow;
  int dir;
}flow_info_t;

typedef struct table_element{
  flow_t *flow;
  pthread_spinlock_t lock;
}flow_table_t;

typedef struct graveyard{
  flow_t *flow;
  int index;
}graveyard_t;

enum flow_dir {NA=0, OUT,IN};  


void printFlow(flow_t *flow);

flow_t *make_flow(pkt_rec_t *pkt_dec);

flow_buffer_t flow_buffer[(FLOW_BUF_NO)];

void flow_process(flow_table_t *table,pkt_rec_t *pkt_dec);

u_int fhash(const pkt_rec_t *pkt);

void put_buff(flow_buffer_t *b, pkt_rec_t *fr);

pkt_rec_t *get_pkt(flow_buffer_t *b);

flow_table_t *new_flow_table();

void add_flow(flow_t *flow, flow_table_t *table);

void flow_collector(graveyard_t *graveyard, flow_table_t *table);

graveyard_t *new_graveyard(int size);

//test
flow_t *get_flow(flow_t *flow, pkt_rec_t *pkt_dec);

#endif
