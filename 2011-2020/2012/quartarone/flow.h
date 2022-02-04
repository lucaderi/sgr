#ifndef __FLOW_H__
#define __FLOW_H__

#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>


/* 2^FLOW_HASH_TAB_SIZE */
#define FLOW_HASH_TAB_SIZE 20

#define FLOW_BUF_NO 4

/* 2^( FLOW_HASH_TAB_SIZE - FLOW_BUF_NO ) */
#define HASH_WINDOW ( FLOW_HASH_TAB_SIZE - FLOW_BUF_NO )

#define FLOW_BUF_SIZE 16284



typedef u_int hash_t;

typedef struct pkt_record{
  hash_t hash;
  struct in_addr src;
  struct in_addr dst;
  u_short size;
  u_short s_port;
  u_short d_port;
  u_char proto;
  struct timeval time;
} pkt_rec_t;

typedef struct flow_buffer{
  sig_atomic_t first;
  sig_atomic_t last;
  int size;
  pkt_rec_t buf[FLOW_BUF_SIZE];
}flow_buffer_t;


typedef struct flow_record{
  /* ID flow record */
  hash_t hash;
  
  struct flow_record *next;

} flow_record_t;


typedef struct flow{
  hash_t hash;
  flow_record_t *first;
}flow_t;


typedef struct hash_table_element{
  flow_t *flow; /* ipotizzo no collisioni */
}ht_elem_t;


flow_buffer_t flow_buffer[(FLOW_BUF_NO)];


u_int fhash(const pkt_rec_t *pkt);

void put_buff(flow_buffer_t *b, pkt_rec_t *fr);

pkt_rec_t *get_buff(flow_buffer_t *b);



#endif
