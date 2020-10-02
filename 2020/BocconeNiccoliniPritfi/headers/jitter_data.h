#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/*
Jitter_data hash map example:

___________________________________________
|stream|      |stream|stream|      |stream|
-------------------------------------------
   | ***
   V
________
|stream| 				***=Eventual conflicts get resolved by making a stream list.
--------

Stream structure:
	____________
	|stream_name|									<ip_source, ip_dest> couple.
	| pkts_num  |	__________	  ___________		Total number of recorded packets.
	|  record   |-->| record  |-->|  record  |      List of records.
	------------   -----------   ------------

Record structure:
	____________
	|t_arrive  |    Packet arrive time.
	|t_delay   |    Packet delay from the previous one.
	|src_port  |    Source port.
	|dst_port  |    Destination port.
	|jitter    |    Evaluated stream jitter when this packet arrives.
	------------
*/

typedef struct record{
	long int t_arrive;
	long int t_delay;      //Delay from previous packet.
  	int src_port;
	int dst_port;
	int jitter;
	struct record *next;
} record;

typedef struct tcp_stream{
	int sum_difference;
	int sum_jitter;
	int anomaly;
	char *stream_name;
	unsigned int pkts_num;
	record *head;
	record *tail;
	struct tcp_stream *next_conflict;
} tcp_stream;

typedef struct anomaly_list{
	int times;
	char *stream_name;
	struct anomaly_list *next;
} anomaly_list;

anomaly_list *a_list;

extern tcp_stream* streams_map;
extern int streams_number;
extern int anomaly_streams_counter;
extern int anomaly_alert_times;

extern void initialize_map(void);
extern int add_record(char *stream_name, long int packet_arrive_time, int src_port, int dst_port);
extern void free_map(void);
