#ifndef _DATA_H
#define _DATA_H
#include <time.h>
#include <stdio.h>

/* Data structure keeping data*/
typedef struct data
{
	unsigned int pkts_no;
	unsigned int bytes;
	
  unsigned int ip_v4;
	unsigned int ip_v4_bytes;
  /* no ipv6 */
	unsigned int not_ip;
	unsigned int not_ip_bytes;
	
  unsigned int tcp;
	unsigned int tcp_bytes;
	unsigned int udp;
	unsigned int udp_bytes;
	unsigned int other;
	unsigned int other_bytes;
} data_t;

typedef struct data_collector
{
	struct data data_out;
	struct data data_in;
	time_t last_up;
} data_collector_t;

/* Resets stats */
//void clear_stats();

/* Print statistics */
//void print_stats(stats_cont_t *st, int inout);

data_collector_t* get_data_collector();

data_collector_t* swap_data();

void init_data();
#endif
