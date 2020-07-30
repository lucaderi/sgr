#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

typedef struct record{
	long int time;
	struct record *next;
} record;

typedef struct tcp_stream{
	float jitter;
	float sum_difference;
	char *stream_name;
	unsigned int pkts_num;
	record *head;
	record *tail;
	struct tcp_stream *next_conflict;
} tcp_stream;

extern tcp_stream* streams_map;

extern void initialize_map(void);
extern int add_record(char *stream_name, long int packet_arrive_time);
extern void print_map(void);
extern void free_map(void);
