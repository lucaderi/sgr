#include "flow.h"
#include <stdio.h>

/* temporanea, non usare*/
u_int fhash(const pkt_rec_t *pkt)
{
	register hash_t h;
	h = pkt->s_port << 16 | pkt->d_port;
	h ^= (h << 16) | (h >> 16);
	h ^= pkt->src.s_addr;
	h ^= pkt->dst.s_addr;
	h ^= pkt->proto;
	h ^= (h << 16) & (~(h >> 16) ^(h & 0xffff));
	h ^= (h << 7) | (h >> 25);
	h ^= (h << 16) & (~(h >> 16) ^(h & 0xffff));
	h ^= (h << 7) | (h >> 25);
	h ^= (h << 16) & (~(h >> 16) ^(h & 0xffff));
	h ^= (h << 7) | (h >> 25);
	h ^= (h << 16) & (~(h >> 16) ^(h & 0xffff));
	return h & ((1<<FLOW_HASH_TAB_SIZE)-1);
}


void put_buff(flow_buffer_t *b, pkt_rec_t *fr){
  if(b->first == b->last)
    fprintf(stderr,"Warning: buffer pineo perdita pacchetti\n");
  else{
    b->buf[b->first] = *fr;
    b->first = (b->first+1) % FLOW_BUF_SIZE;
    b->size++;
  }
}

pkt_rec_t* get_buff(flow_buffer_t *b){
  u_int next;
  if( (next = (b->last+1) % FLOW_BUF_SIZE) == b->first)
    return NULL;
  b->last = next;
  return &b->buf[next];
}



