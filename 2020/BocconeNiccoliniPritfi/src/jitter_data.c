#include "jitter_data.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>


#define SIZE 30
#define A 999
#define B 9758
#define P 999149
#define HASH(s) ((atoi(s) * A + B) % P) % SIZE

int add_to_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time);
int add_new_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time);
long int add_packet_record(record **head, record **tail, long int packet_arrive_time);

tcp_stream* streams_map;

// initialize hashmap
void initialize_map() {
	streams_map = (tcp_stream *) malloc(sizeof(tcp_stream) * SIZE);
	int i;
	tcp_stream *tmp;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		tmp->jitter = 0;
		tmp->sum_difference = 0;
		tmp->stream_name = NULL;
		tmp->pkts_num = 0;
		tmp->head = NULL;
		tmp->tail = NULL;
		tmp->next_conflict = NULL;
	}
return;
}

int add_record(char *stream_name, long int packet_arrive_time){
	if(stream_name == NULL){
		fprintf(stderr, "jitter_data.add_record: NULL stream name.\n");
		return -1;
	}
	//printf("ip: %s, time: %ld\n", stream_name, packet_arrive_time);
	int map_index = HASH(stream_name);
	tcp_stream *tmp = &streams_map[map_index];
	if(tmp->stream_name == NULL){
		//Empty stream slot
		return add_new_stream(tmp, stream_name, packet_arrive_time);
	}
	else {
		//May be conflicts
		return add_to_stream(tmp, stream_name, packet_arrive_time);
	}
}

int add_to_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time){
	while(strcmp(stream->stream_name, stream_name) != 0 && stream->next_conflict != NULL){
		stream = stream->next_conflict;
	}
	if(strcmp(stream->stream_name, stream_name) == 0){
		long int difference;
		//printf("CONNECTION ALREADY SEE\n");
		stream->pkts_num++;   // in this case i already see the connection
		difference = add_packet_record(&stream->head, &stream->tail, packet_arrive_time);
		stream->sum_difference += difference;
		stream->jitter = stream->sum_difference / (stream->pkts_num-1);
		printf("\n   Comunication: %s\n", stream->stream_name);
		printf("         Jitter(ms): %.1f\n", stream->jitter);
		printf("Packets sniffed: %d [\n", stream->pkts_num);
		printf("                   ]\n");
		return 1;
	} else if(stream->next_conflict == NULL){
			//new stream
			stream->next_conflict = (tcp_stream *) malloc(sizeof(tcp_stream));
			tcp_stream *new_stream = stream->next_conflict;
			new_stream->stream_name = stream_name;
			new_stream->jitter = 0;
			new_stream->sum_difference = 0;
			new_stream->pkts_num = 1;
			new_stream->head = NULL;
			new_stream->tail = NULL;
			new_stream->next_conflict = NULL;
			add_packet_record(&new_stream->head, &new_stream->tail, packet_arrive_time);
			return 1;
	}
	else
		return -1;
}

int add_new_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time){
	stream->stream_name = stream_name;
	stream->pkts_num = stream->pkts_num + 1;
	add_packet_record(&stream->head, &stream->tail, packet_arrive_time);
	return 1;
}

// return the difference between end time and start time
// if there are two or many packets, 0 otherwise
long int add_packet_record(record **head, record **tail, long int packet_arrive_time){
	if(*head == NULL){
		*head = (record *) malloc(sizeof(record));
		(*head)->next = NULL;
		tail = head;
		(*head)->time = packet_arrive_time;
	}
	else{
		record *new_el = (record *) malloc(sizeof(record));
		long int difference = packet_arrive_time - (*head)->time;
		new_el->time = packet_arrive_time;
		new_el->next = *head;
		*head = new_el;
		return difference;
	}
	return 0;
}

void print_stream(tcp_stream *str){
	if(str->stream_name == NULL)
		return;

	printf("\n   Comunication: %s\n", str->stream_name);
	printf("         Jitter(ms): %.1f\n", str->jitter);
	printf("Packets sniffed: %d [\n", str->pkts_num);
	record *tmp_r = str->head;
	int packet_num = 1;
	while(tmp_r != NULL){
		printf("                    Packet %d arrived at time %ld;\n", packet_num, tmp_r->time);
		packet_num++;
		tmp_r = tmp_r->next;
	}
	printf("                   ]\n");
	return;
}

void print_map(void){
	printf("Recorded streams:\n");
	int i;
	tcp_stream *tmp;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			print_stream(tmp);
			tmp = tmp->next_conflict;
		}
	}
	return;
}


// free stream memory
void free_stream(tcp_stream *str) {
	if(str->stream_name == NULL)
		return;
	record *tmp_r = str->head;
	while(tmp_r != NULL){
		str->head = str->head->next;
		free(tmp_r);
		tmp_r = str->head;
	}
	return;
}

// free all memory of the hashmap
void free_map(void) {
	tcp_stream *tmp, *aux;
	int i;
	for(i = 0; i < SIZE; i++)
		tmp = &streams_map[i];
		while(tmp != NULL){
			free_stream(tmp);
			free(tmp->stream_name);
			free(tmp->head);
			free(tmp->tail);
			aux = tmp->next_conflict;
			free(tmp->next_conflict);
			tmp = aux;
		}
		return;
}
