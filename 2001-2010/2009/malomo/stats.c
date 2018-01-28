#include "stats.h"
#include "utils.h"
#include <strings.h>

void print_stat(stats_t *stat)
{
	if (stat)
	{
		printf("total packets: %d\n", stat->pkts_no);
		printf("LAYER 3:\n  ipv4: %d pkts  %d bytes\n", stat->ip, stat->ip_bytes);
		printf("  ipv6: %d pkts  %d bytes\n", stat->ip6, stat->ip6_bytes);
		printf("  not ip: %d pkts  %d bytes\n", stat->not_ip, stat->not_ip_bytes);
		printf("LAYER 4:\n  tcp: %d pkts  %d bytes\n", stat->tcp, stat->tcp_bytes);
		printf("  udp: %d pkts  %d bytes\n", stat->udp, stat->udp_bytes);
		printf("  others: %d pkts  %d bytes\n", stat->other, stat->other_bytes);
	}
}

void print_stats(stats_cont_t *st, int inout)
{
	/*stats_cont_t *st;
	spinlock_lock(&stats_lock);
	st = stats_ptr;
	spinlock_unlock(&stats_lock);*/
	if (!st) return;
	
	if (inout)
	{
		printf("IN TRAFFIC -------------\n");
		print_stat(&st->stats_in);
		printf("\nOUT TRAFFIC -------------\n");
		print_stat(&st->stats_out);
	}
	else
	{
		printf("TRAFFIC ----------------\n");
		print_stat(&st->stats_in);
	}
}

spinlock_t stats_lock;
volatile int stat_index = 0;
stats_cont_t stats_buf[2];
stats_cont_t *stats_ptr = &stats_buf[0];

void clear_stats()
{
	bzero(&stats_buf, 2*sizeof(stats_cont_t));
}

stats_cont_t* get_stats_container()
{
	stats_cont_t * st;
	spinlock_lock(&stats_lock);
	st = stats_ptr;
	spinlock_unlock(&stats_lock);
	return st;
}

stats_cont_t* swap_stats_buffers()
{
	stats_cont_t * stats;
	int index = stat_index;
	stat_index = stat_index ^ 1;
	stats = &stats_buf[stat_index];
	spinlock_lock(&stats_lock);
	stats_ptr = stats;
	spinlock_unlock(&stats_lock);
	return &stats_buf[index];
}

void init_stats()
{
	clear_stats();
	create_spinlock(&stats_lock);
}

void dispose_stats()
{
	destroy_spinlock(&stats_lock);
}