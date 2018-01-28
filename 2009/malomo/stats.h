#ifndef _STATS_H
#define _STATS_H
#include <time.h>
#include <stdio.h>

/* Data structure keeping stats*/
typedef struct stats
{
	/* Layer 2 */
	unsigned int pkts_no;
	unsigned int bytes;
	/* Layer 3 */
	unsigned int ip;
	unsigned int ip_bytes;
	unsigned int ip6;
	unsigned int ip6_bytes;
	unsigned int not_ip;
	unsigned int not_ip_bytes;
	/* Layer 4 */
	unsigned int tcp;
	unsigned int tcp_bytes;
	unsigned int udp;
	unsigned int udp_bytes;
	unsigned int other;
	unsigned int other_bytes;
} stats_t;

/* Container structure for stats */
typedef struct stats_cont
{
	/* time of the last update*/
	time_t last_up;
	/* Stats for in-data (in/out in case mac address is unknown)*/
	struct stats stats_in;
	/* Stats for out-data */
	struct stats stats_out;
} stats_cont_t;

/* Resets stats */
void clear_stats();

/* Print statistics */
void print_stats(stats_cont_t *st, int inout);

/* Returns the actual stats container */
stats_cont_t* get_stats_container();

/* Inverts the stats buffers returning the currently unused one */
stats_cont_t* swap_stats_buffers();

/* Cleanup statistics structures */
void dispose_stats();

/* initialize statistics structures */
void init_stats();
#endif
