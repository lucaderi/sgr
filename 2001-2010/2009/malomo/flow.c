#include "flow.h"
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>

hash_t hash(const pkt_t* pkt)
{
	register hash_t h;
	h = pkt->src_port << 16 | pkt->dst_port;
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
	return h & HASHMASK;
}

table_element_t * create_flow_table()
{
	table_element_t *table;
	int i;
	CALLOC(table, HASHSIZE, sizeof(table_element_t), NULL)
	for (i=0; i<HASHSIZE; i++)
	{
		create_spinlock(&(table[i].lock));
	}
	return table;
}

match_t match(pkt_t* pkt, flow_t* entry)
{
	if (pkt->proto == entry->proto)
	{
		if (pkt->src.s_addr == entry->addr1
			&& pkt->src_port == entry->port1
			&& pkt->dst.s_addr == entry->addr2
			&& pkt->dst_port == entry->port2)
			return DIR1;
		if (pkt->src.s_addr == entry->addr2
			&& pkt->src_port == entry->port2
			&& pkt->dst.s_addr == entry->addr1
			&& pkt->dst_port == entry->port1)
			return DIR2;
	}
	return NO_MATCH;
}

void print_flow(flow_t* f)
{
	char addr1[16], addr2[16];
	printf("%s %15s:%-5d <-> %15s:%-5d  bytes>>:%lu  pkts>>:%lu  bytes<<:%lu  pkts<<:%lu  lasted: %lu seconds - started: %s",
		   getprotobynumber(f->proto)->p_name,
		   strncpy (addr1, inet_ntoa(*((struct in_addr*) &f->addr1)), 16),
		   f->port1,
		   strncpy (addr2, inet_ntoa(*((struct in_addr*) &f->addr2)), 16),
		   f->port2,
		   f->bytes1,
		   f->pkts1,
		   f->bytes2,
		   f->pkts2,
		   f->last_time.tv_sec - f->start_time.tv_sec,
		   ctime(&f->start_time.tv_sec));
}

static flow_t *graveyard[FREE_LIST_SIZE];
static int graveyard_index = 0;

void remove_flow(flow_t* rem)
{
	flow_t * f = graveyard[graveyard_index];
	if (f) free(f);
	print_flow(rem);
	graveyard[graveyard_index] = rem;
	graveyard_index = (graveyard_index+1) % FREE_LIST_SIZE;
}

void* flow_collector(void* args)
{
	u_long i;
	struct timeval timeval;
	time_t last_time, curr_time;
	int list_index = 0;
	flow_t **prev, *curr;
	table_element_t *table = (table_element_t *)args;
	
	/* Free list reset */
	for (i=0; i<FREE_LIST_SIZE; i++)
		graveyard[i] = NULL;
	
	for (;;)
	{
		sleep(FLOW_COLLECTOR_INTERVAL);
		
		/* Get system time */
		gettimeofday(&timeval, NULL);
		curr_time = timeval.tv_sec;
		
		/* Collect and emit flows */
		for (i=0; i<HASHSIZE; i++)
		{
			list_index = 0;
			prev = &table[i].first;
			curr = table[i].first;
			while (curr)
			{
				last_time = curr->last_time.tv_sec;
				if ((curr_time - last_time) > FLOW_EXPIRE_TIME ||
					(last_time - curr->start_time.tv_sec) > FLOW_MAX_TIME)
				{
					spinlock_lock(&table[i].lock);
					if (list_index == 0 && *prev != curr)
					{
						curr = table[i].first;
						spinlock_unlock(&table[i].lock);
						continue;
					}
					*prev = curr->next;
					spinlock_unlock(&table[i].lock);
					remove_flow(curr);
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
	return NULL;
}

int flow_process_pkt(pkt_t* pkt, table_element_t* table, flow_t **allocated)
{
	flow_t *curr/*, **prev*/;
	match_t m;
	table_element_t *t = table + pkt->hash;
	if (!pkt)
	{
		fprintf(stderr,"error\n");
		return 0;
	}
	/* Critical section */
	curr = t->first;
	while (curr)
	{
		if ((m = match(pkt, curr))) break;
		/*prev = &curr->next;*/
		curr = curr->next;
	}
	if (curr)
	{
		/* Update flow */
		if (m == DIR1)
		{
			curr->bytes1 += pkt->size;
			curr->pkts1++;
		}
		else
		{
			curr->bytes2 += pkt->size;
			curr->pkts2++;
		}
		curr->last_time = pkt->time;
		/* TODO check wheter a flow lasted too much */
		/*if ((curr->last_time.tv_sec - curr->start_time.tv_sec) > FLOW_MAX_TIME)
		{
			print_flow(curr);
			remove_flow(curr, prev);
		}*/
	}
	else
	{
		/* Create Flow */
		flow_t *e;
		if (!(e = *allocated))
		{
			fprintf(stderr, "ENOMEM\n");
			return errno;
		}
		/* Fill */
		e->addr1 = pkt->src.s_addr;
		e->addr2 = pkt->dst.s_addr;
		e->port1 = pkt->src_port;
		e->port2 = pkt->dst_port;
		e->proto = pkt->proto;
		e->bytes1 = pkt->size;
		e->pkts1 = 1;
		e->start_time = e->last_time = pkt->time;
		
		/* Insert (in head, always) */
		spinlock_lock(&t->lock);
		e->next = t->first;
		t->first = e;
		spinlock_unlock(&t->lock);
		*allocated = NULL;
	}
	return 0;
}

/* QUEUE functions */
void init_queue(queue_t* q)
{
	if (q)
	{
		q->first = 1;
		q->last = 0;
	}
}

void enqueue(queue_t* q, pkt_t* p)
{
	if ( q->first == q->last)
		/* Queue full - Drop packet */
		fprintf(stderr, "Warning: queue overflow (enqueue) %d %d\n", q->first, q->last);
	else
	{
		q->q[q->first] = *p;
		q->first = (q->first+1) % QUEUE_SIZE;
	}
}

pkt_t* dequeue(queue_t* q)
{
	u_int next;
	if ((next = (q->last+1) % QUEUE_SIZE) == q->first)
		/* Queue empty */
		return NULL;
	q->last = next;
	return q->q + next;
}

void* flow_processor(void* args)
{
	table_element_t *table;
	queue_t *q;
	pkt_t *p;
	int i = 0;
	flow_t *f;
	
	flow_processor_args_t *arg = (flow_processor_args_t*)args;
	table = arg->table;
	q = arg->q;
	
	f = calloc(1, sizeof(flow_t));
	for (;;)
	{
		p = dequeue(q);
		if (!f)
			f = calloc(1, sizeof(flow_t));
		if (p)
		{
			flow_process_pkt(p, table, &f);
			i = 0;
		} else
		{
			if (++i == 100000)
			{
				/* Sleep (avoid melting the cpu) */
				usleep(10000);
				i = 0;
			}
		}
	}
}
