#include "jitter_data.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/*This files defines an hash map used to store informations about captured packets.
  For every stream (pair of <ip_source, ip_dest>) details like jitter and arrive time of
  each packet gets estimated and saved.
*/

/*Hash map details.*/
#define SIZE 30
#define A 999
#define B 9758
#define P 999149
#define HASH(s) ((atoi(s) * A + B) % P) % SIZE
#define RED     "\033[31m"      /* Red */
#define RESET   "\033[0m"

//Add a captured packet to an already registered stream.
int  add_to_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time, int src_port, int dst_port);
//Add a captured packet to a stream that has never been encountered.
int  add_new_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time, int src_port, int dst_port);
//Append the new packet records to a stream.
int add_packet_record(record **head, record **tail, long int packet_arrive_time, int src_port, int dst_port);
//Add the stream name to the anomaly list
void add_anomaly_list(char *anomaly_name);
//Update the jitter value for a communication and add the stream name to the anomaly list if thresholds are not respect
void update_jitter(tcp_stream *stream);

//Main data structure.
tcp_stream* streams_map;
long int start;

void initialize_map() {
	streams_map = (tcp_stream *) malloc(sizeof(tcp_stream) * SIZE);
	int i;
	a_list = NULL;
	tcp_stream *tmp;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		tmp->anomaly = 0;
		tmp->sum_jitter = 0;
		tmp->sum_difference = 0;
		tmp->stream_name = NULL;
		tmp->pkts_num = 0;
		tmp->head = NULL;
		tmp->tail = NULL;
		tmp->next_conflict = NULL;
	}
	return;
}

// add the stream name to the anomaly list
void add_anomaly_list(char *anomaly_name){
	if(a_list == NULL){
		a_list = malloc(sizeof(anomaly_list));
		a_list->stream_name = anomaly_name;
		a_list->next = NULL;
	}
	else{
		anomaly_list *new = malloc(sizeof(anomaly_list));
		new->stream_name = anomaly_name;
		new->next = a_list;
		a_list = new;
	}
}

//Update the jitter value for a communication and add the stream name to the anomaly list if thresholds are not respect
void update_jitter(tcp_stream *stream){
	int average, min_threshold, max_threshold;
	stream->head->jitter = stream->sum_difference / (stream->pkts_num - 1);
	printf("Jitter calcolato con update_jitter: %d\n", stream->head->jitter);

	average = stream->sum_jitter / (stream->pkts_num-1);
	max_threshold = average * 1.5;
	min_threshold = average * 0.5;
	if((stream->head->jitter > max_threshold || stream->head->jitter < min_threshold) && stream->pkts_num > 4){
		if( stream->anomaly == 0){
			add_anomaly_list(stream->stream_name);
			stream->anomaly = 1;
		}
		printf(RED "	Comunicazione: %s, Jitter ANOMALO!,num_packets: %d, Average: %d, min_threshold: %d, max_threshold: %d\n" RESET, stream->stream_name, stream->pkts_num, average, min_threshold, max_threshold);
	}


	stream->sum_jitter += stream->head->jitter;
}

//If the packet belongs to an already existing stream calls add_to_stream, add_new_stream otherwise.
int add_record(char *stream_name, long int packet_arrive_time, int src_port, int dst_port){
	if(stream_name == NULL){
		fprintf(stderr, "jitter_data.add_record: NULL stream name.\n");
		return -1;
	}
	int map_index = HASH(stream_name);
	tcp_stream *tmp = &streams_map[map_index];
	if(tmp->stream_name == NULL){
		//Empty stream slot
		return add_new_stream(tmp, stream_name, packet_arrive_time, src_port, dst_port);
	}
	else {
		//May be conflicts
		return add_to_stream(tmp, stream_name, packet_arrive_time, src_port, dst_port);
	}
}

//Add a captured packet to an already registered stream.
int add_to_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time, int src_port, int dst_port){
	while(strcmp(stream->stream_name, stream_name) != 0 && stream->next_conflict != NULL){
		stream = stream->next_conflict;
	}
	if(strcmp(stream->stream_name, stream_name) == 0){
		stream->pkts_num = stream->pkts_num + 1;
		stream->sum_difference += add_packet_record(&stream->head, &stream->tail, packet_arrive_time, src_port, dst_port);
		if(stream->pkts_num >= 2)
			update_jitter(stream);

		return 1;
	} else if(stream->next_conflict == NULL){
			//new stream to monitor!
			stream->next_conflict = (tcp_stream *) malloc(sizeof(tcp_stream));
			tcp_stream *new_stream = stream->next_conflict;
			new_stream->stream_name = stream_name;
			new_stream->sum_jitter = 0;
			new_stream->anomaly = 0;
			new_stream->sum_difference = 0;
			new_stream->pkts_num = 1;
			new_stream->head = NULL;
			new_stream->tail = NULL;
			new_stream->next_conflict = NULL;
			add_packet_record(&new_stream->head, &new_stream->tail, packet_arrive_time, src_port, dst_port);
			return 1;
	}
	else
		return -1;
}

//Add a captured packet to a communication that has never been encountered.
int add_new_stream(tcp_stream *stream, char *stream_name, long int packet_arrive_time, int src_port, int dst_port){
	stream->stream_name = stream_name;
	stream->pkts_num = stream->pkts_num + 1;
	add_packet_record(&stream->head, &stream->tail, packet_arrive_time, src_port, dst_port);
	return 1;
}

//Append the new packet records to a stream.
int add_packet_record(record **head, record **tail, long int packet_arrive_time, int src_port, int dst_port){
	if(*head == NULL){
		*head = (record *) malloc(sizeof(record));
		(*head)->next = NULL;
		tail = head;
		(*head)->t_arrive = packet_arrive_time;
		(*head)->t_delay = 0;
		(*head)->jitter = 0;
		(*head)->src_port = src_port;
		(*head)->dst_port = dst_port;
		return (*head)->t_delay;
	}
	else{
		record *new_el = (record *) malloc(sizeof(record));
		new_el->t_arrive = packet_arrive_time;
		new_el->t_delay =  packet_arrive_time - (*head)->t_arrive;
		new_el->src_port = src_port;
		new_el->src_port = dst_port;
		new_el->jitter = 0;
		new_el->next = *head;
		*head = new_el;
		return new_el->t_delay;
	}

}

void print_record(record *tmp_r, int pkts_num){
	if(tmp_r == NULL)
		return;

	print_record(tmp_r->next, pkts_num - 1);
	if(pkts_num == 1)
		printf("                    [Packet %d] Arrive time: %ld. Ports: %d -> %d;\n", pkts_num, tmp_r->t_arrive, tmp_r->src_port, tmp_r->dst_port);
	else
		printf("                    [Packet %d] Arrive time: %ld. Delay from previous packet: %ld. Ports: %d -> %d. Jitter: %d;\n", pkts_num, tmp_r->t_arrive, tmp_r->t_delay, tmp_r->src_port, tmp_r->dst_port, tmp_r->jitter);
}

void print_stream(tcp_stream *str){
	if(str->stream_name == NULL)
		return;
	printf("\n   Comunication: %s\n", str->stream_name);

	printf("Packets sniffed: %d [\n", str->pkts_num);
	record *tmp_r = str->head;
	print_record(tmp_r, str->pkts_num);
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

void save_record(FILE *fp, record *tmp_r){
	if(tmp_r == NULL)
		return;

	save_record(fp, tmp_r->next);
	fprintf(fp, "%le %le\n", (double)(tmp_r->t_arrive - start), (double)tmp_r->jitter);
}

void save_stream(tcp_stream *str){
	if(str->stream_name == NULL)
		return;
	char name_file[40];
	strcpy(name_file, str->stream_name);
	strcat(name_file, ".txt");
	FILE *fp = fopen (name_file,"w");
	record *tmp_r = str->head;
	save_record(fp, tmp_r);
	fclose(fp);
}

//Save to file all recorded data from every stream encountered.
void save_map(long int s){
	int i;
	tcp_stream *tmp;
	start = s;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			save_stream(tmp);
			tmp = tmp->next_conflict;
		}
	}
}

void print_anomaly_list(){
	anomaly_list *aux = a_list;
	printf("\nAnomaly list:\n");
	while(aux != NULL){
		printf(RED "%s\n" RESET, aux->stream_name);
		aux = aux->next;
	}
	printf("**********\n");
}
