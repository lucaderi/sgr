#include "flow.h"
#include <stdio.h>
#include <string.h>

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

int compare(pkt_rec_t *pkt, flow_t *flow){
 if(pkt->proto == flow->proto){
   if(pkt->src.s_addr == flow->addr_dir1.s_addr &&
     pkt->s_port == flow->port_dir1 &&
     pkt->dst.s_addr == flow->addr_dir2.s_addr &&
     pkt->d_port == flow->port_dir2)
     return 1;
   if(pkt->src.s_addr == flow->addr_dir2.s_addr &&
     pkt->s_port == flow->port_dir2 &&
     pkt->dst.s_addr == flow->addr_dir1.s_addr &&
     pkt->d_port == flow->port_dir1)
     return 2;
 }
 return -1;

}


void printFlow(flow_t *flow){
  printf("|------------------------\n");
  printf("| addr_dir1: %s | port_dir1: %d\n",inet_ntoa(flow->addr_dir1), flow->port_dir1);
  printf("| addr_dir2: %s | port_dir2: %d\n",inet_ntoa(flow->addr_dir2), flow->port_dir2);
  printf("| proto: %d\n",flow->proto);
  printf("| npkt_dir1: %d | npkt_dir2: %d\n", flow->npkt_dir1, flow->npkt_dir2);
  printf("|\n");
}

graveyard_t *new_graveyard(int size){
  graveyard_t *g;
  g = (graveyard_t*) malloc(sizeof(graveyard_t));
  g->flow = calloc(size,sizeof(flow_t));
  g->index = 0;
  return g;
}

flow_table_t *new_flow_table(){
  flow_table_t *tab;
  tab = calloc((1<<FLOW_HASH_TAB_SIZE),sizeof(flow_table_t));
  int i;
  for(i=0; i<(1<<FLOW_HASH_TAB_SIZE); i++){
    pthread_spin_init(&tab[i].lock, PTHREAD_PROCESS_PRIVATE);   
  }
  return tab;
}


flow_info_t *get_flow_info(flow_t *flow, pkt_rec_t *pkt_dec, flow_info_t *info){
  int dir = -1;
  while(flow){
    if((dir = compare(pkt_dec,flow)) > 0 )
      break; 
    flow = flow->next;
  }
  info->flow = flow;
  info->dir = dir;
  return info;
}

flow_t *get_flow(flow_t *flow, pkt_rec_t *pkt_dec){
  while(flow){
    if( compare(pkt_dec,flow) > 0 )
      break; 
    flow = flow->next;
  }
  return flow;
}



flow_t *update_flow(flow_t *flow, pkt_rec_t *pkt_dec, int dir){

 if( dir == 1){
      flow->b_dir1 += pkt_dec->size;
      flow->npkt_dir1++;
 }else{
      flow->b_dir2 += pkt_dec->size;
      flow->npkt_dir2++;
 }
 flow->l_time = pkt_dec->time;
 return flow;
}

void add_flow(flow_t *flow, flow_table_t *table){
  flow_table_t *tab;
  tab = table;
  flow->next = tab->flow;
  tab->flow = flow;
}


void remove_flow(flow_t* rem, graveyard_t *grave){
	flow_t * f;
  f = &grave->flow[grave->index];
  bzero(f,sizeof(flow_t));
	grave->flow[grave->index] = *rem;
	grave->index = (grave->index+1) % FREE_LIST_SIZE;
}


void flow_collector(graveyard_t *graveyard, flow_table_t *table){
	u_long i;
	struct timeval timeval;
	time_t last_time, curr_time;
	int list_index = 0;
	flow_t **prev, *curr;
		
		/* Get system time */
		gettimeofday(&timeval, NULL);
		curr_time = timeval.tv_sec;
		
		/* Collect and emit flows */
		for (i=0; i<(1<<FLOW_HASH_TAB_SIZE); i++)
		{
			list_index = 0;
			prev = &table[i].flow;
			curr = table[i].flow;
			while (curr)
			{
				last_time = curr->l_time.tv_sec;
				if ((curr_time - last_time) > FLOW_EXPIRE_TIME ||
					(last_time - curr->s_time.tv_sec) > FLOW_MAX_TIME)
				{
					pthread_spin_lock(&table[i].lock);
					if (list_index == 0 && *prev != curr)
					{
						curr = table[i].flow;
						pthread_spin_unlock(&table[i].lock);
						continue;
					}
					*prev = curr->next;
					pthread_spin_unlock(&table[i].lock);
					remove_flow(curr, graveyard);
					curr = curr->next;
				}
				else
				{
					prev = &curr->next;
					curr = curr->next;
					list_index++;
				}
			}
    }
}


flow_t *make_flow(pkt_rec_t *pkt_dec){
  flow_t *flow;
  flow = (flow_t* )malloc( sizeof(flow_t));
    flow->addr_dir1.s_addr = pkt_dec->src.s_addr;
    flow->addr_dir2.s_addr = pkt_dec->dst.s_addr;
    flow->port_dir1 = pkt_dec->s_port;
    flow->port_dir2 = pkt_dec->d_port;
    flow->proto = pkt_dec->proto;
    flow->b_dir1 = pkt_dec->size;
    flow->b_dir2 = 0;
    flow->npkt_dir1 = 1;
    flow->npkt_dir2 = 0;
  flow->s_time = pkt_dec->time;
  return flow;
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

pkt_rec_t* get_pkt(flow_buffer_t *b){
  u_int next;
  if( (next = (b->last+1) % FLOW_BUF_SIZE) == b->first)
    return NULL;
  b->last = next;
  b->size--;
  return &b->buf[next];
}


