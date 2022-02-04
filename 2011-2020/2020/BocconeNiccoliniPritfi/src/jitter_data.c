#include "jitter_data.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

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

//Free all memory allocated by saved data.
void free_map();
void free_stream(tcp_stream *str);
void free_record(record *tmp_r);
void free_anomaly_list(anomaly_list *list);

//Main data structure.
tcp_stream *streams_map;
long int start;
int streams_number = 0;
int anomaly_alert_times = 0;
int anomaly_streams_counter = 0;
char *name;
int uid;

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
	name = getlogin();
	struct passwd *p;
	p = getpwnam(name);

	uid =(int)p->pw_uid;
	return;
}

// add the stream name to the anomaly list
void add_anomaly_list(char *anomaly_name){
	if(a_list == NULL){
		a_list = malloc(sizeof(anomaly_list));
		a_list->stream_name = anomaly_name;
		a_list->next = NULL;
		a_list->times = 1;
	}
	else{
		anomaly_list *new = malloc(sizeof(anomaly_list));
		new->stream_name = anomaly_name;
		new->next = a_list;
		new->times = 1;
		a_list = new;
	}
}

void increase_anomaly_times(char *anomaly_name){
	if(a_list == NULL){
		perror("increase_anomaly_times = NULL");
		exit(EXIT_FAILURE);
	}
	anomaly_list *tmp = a_list;
	while(tmp != NULL){
		if(strcmp(tmp->stream_name, anomaly_name) == 0)
			break;
		tmp = tmp->next;
	}
	tmp->times = tmp->times + 1;
	return;
}

void send_notification(char *title, char *message){
	char *notif = malloc(sizeof(char)*200);
	sprintf(notif, "sudo -u %s DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus notify-send '%s' '%s'", name, uid, title, message);
	system(notif);
	free(notif);
}

//Update the jitter value for a communication and add the stream name to the anomaly list if thresholds are not respect
void update_jitter(tcp_stream *stream){
	int average, min_threshold, max_threshold;
	stream->head->jitter = stream->sum_difference / (stream->pkts_num - 1);

	average = stream->sum_jitter / (stream->pkts_num-1);
	max_threshold = average * 1.5;
	min_threshold = average * 0.5;
	if((stream->head->jitter > max_threshold || stream->head->jitter < min_threshold) && stream->pkts_num > 4){
		anomaly_alert_times++;
		if(stream->anomaly == 0){
			char *message = malloc(sizeof(char) * 128);
			sprintf(message, "Anomaly observed in <IP_src,IP_dst>:\n %s", stream->stream_name);
			send_notification("Suspicious jitter variation detected", message);
			anomaly_streams_counter++;
			add_anomaly_list(stream->stream_name);
			stream->anomaly = 1;
			free(message);
		}
		else{
			increase_anomaly_times(stream->stream_name);
		}
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
			streams_number++;
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
	streams_number++;
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
		new_el->dst_port = dst_port;
		new_el->jitter = 0;
		new_el->next = *head;
		*head = new_el;
		return new_el->t_delay;
	}

}

//Free all memory allocated by saved data.
void free_map(){
	int i;
	tcp_stream *tmp;
	tcp_stream *tmp_prev;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		free_stream(tmp);
		tmp = tmp->next_conflict;
		while(tmp != NULL){
			free_stream(tmp);
			tmp_prev = tmp;
			tmp = tmp->next_conflict;
			free(tmp_prev);
		}
	}
	free(streams_map);
	free_anomaly_list(a_list);
	return;
}

void free_stream(tcp_stream *str){
	if(str == NULL)
		return;
	if(str->stream_name != NULL)
		free(str->stream_name);

	free_record(str->head);
}

void free_record(record *tmp_r){
	if(tmp_r == NULL)
		return;
	free_record(tmp_r->next);
	free(tmp_r);
}

void free_anomaly_list(anomaly_list *list){
	if(list == NULL)
		return;

	free_anomaly_list(list->next);
	free(list);
}
