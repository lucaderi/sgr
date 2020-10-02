#define _XOPEN_SOURCE 500
#include <stdio.h>
#include "menu.h"
#include "jitter_data.h"
#include "gnuplot_i.h"
#include <ftw.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*This file implements a set of functions to print data and
	show a navigable menu by the user.*/


#define SIZE 30
#define RED     "\033[31m"      /* Red */
#define RESET   "\033[0m"

//Print menu and let the user navigate through all possible operations.
void main_menu();

void detailed_streams_print();

void short_streams_print();

void suspicious_streams_print();

void draw_stream();

//Change ownership and read/write/modify permissions of a file.
void set_permissions(char *file, mode_t mode);

//Get and cast to integer the terminal input.
int get_int_input();

//Returns the stream on the <index> position.
//<flag> = { 1  => count only suspicious connections.
//				 { 0  => count all connections.
tcp_stream *stream_lookup(int index, int flag);

//Returns an array containing all jitter values in the <str> communication.
double *get_stream_values(tcp_stream *str);

int ask_to_save();

//Function to print packet info.
void print_record(record *tmp_r, int pkts_num);

void print_stream(tcp_stream *str);

//Print every connections and their informations.
void print_map(void);

//Show every connection only by name.
void print_short_map();

//Print connections with suspicious variation of their jitter.
void print_anomaly_list();

void print_summary();

 /**********Implementation***********/

//Function to print packet info.
void print_record(record *tmp_r, int pkts_num){
	if(tmp_r == NULL)
		return;

	print_record(tmp_r->next, pkts_num - 1);

	long int time_in_sec = tmp_r->t_arrive / 1000;

	char buf[80];
	struct tm ts = *localtime(&time_in_sec);
  	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
	if(pkts_num == 1)
		printf(" [Packet %d] Arrive time: %s. Ports: %d -> %d\n", pkts_num, buf, tmp_r->src_port, tmp_r->dst_port);
	else{
		if(tmp_r->t_delay == 0)
			printf(" [Packet %d] Arrive time: %s. Delay from previous packet: < 1 ms. Ports: %d -> %d. Jitter: %d ms\n", pkts_num, buf, tmp_r->src_port, tmp_r->dst_port, tmp_r->jitter);
		else
			printf(" [Packet %d] Arrive time: %s. Delay from previous packet: %ld ms. Ports: %d -> %d. Jitter: %d ms\n", pkts_num, buf, tmp_r->t_delay, tmp_r->src_port, tmp_r->dst_port, tmp_r->jitter);
	}
}

void print_stream(tcp_stream *str){
	if(str->stream_name == NULL)
		return;
	if(str->anomaly == 1)
				printf(RED);
	printf(" Communication: %s\n", str->stream_name);

	printf(" Packets sniffed: %d [\n", str->pkts_num);
	record *tmp_r = str->head;
	print_record(tmp_r, str->pkts_num);
	printf("                    ]\n" RESET);
	return;
}

//Print every connections and their informations.
void print_map(void){
	printf("Recorded streams:\n");
	int i;
	int j = 0;
	tcp_stream *tmp;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			if(tmp->stream_name != NULL){
				j++;
				printf("\n%d) ", j);
			}
			print_stream(tmp);
			tmp = tmp->next_conflict;
		}
	}
	return;
}

//Show every connection only by name.
void print_short_map(){
	int i;
	int j = 0;
	tcp_stream *tmp;
	printf("       Recorded communications:\n");
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			if(tmp->stream_name != NULL){
				j++;
				printf("\n%d) ", j);
				if(tmp->anomaly == 1)
							printf(RED);
				printf(" %s\n" RESET, tmp->stream_name);
			}
			tmp = tmp->next_conflict;
		}
	}
	return;
}

//Print connections with suspicious variation of their jitter.
void print_anomaly_list(){
	if(anomaly_streams_counter == 0){
		printf("\nNo suspicious connections detected!\n");
		return;
	}
	printf("\nSuspicious connections:\n");
	int i;
	int j = 0;
	tcp_stream *tmp;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			if(tmp->stream_name != NULL && tmp->anomaly == 1){
				j++;
				printf("\n%d) ", j);
				print_stream(tmp);
			}
			tmp = tmp->next_conflict;
		}
	}
}

void print_summary(){
	printf("Number of communications (different <IP_scr,IP_dst> pairs) analyzed: %d\n", streams_number);
	if(a_list == NULL){
		printf("No suspicious jitter variations detected.\n");
	}
	else
		printf(RED"%d suspicious jitter variations detected in %d different communications.\n"RESET, anomaly_alert_times, anomaly_streams_counter);

	return;
}

//Change ownership and read/write/modify permissions of a file.
void set_permissions(char *file, mode_t mode){
	pid_t id = getpid();
	chmod(file, mode);
	chown(file, id, id);
	return;
}

//Get and cast to integer the terminal input.
int get_int_input(){
	char* str_value = malloc(sizeof(char) * 21);
	scanf(" %s", str_value);
	int int_value = atoi(str_value);
	free(str_value);
	return int_value;
}

//Print menu and let the user navigate through all possible operations.
void main_menu(){
	DIR* dir = opendir("./graphs");
	if (dir) {
	    closedir(dir);
			mkdir("./graphs", 0700);
			set_permissions("graphs", S_IXOTH | S_IROTH | S_IWOTH | S_IXGRP | S_IRGRP | S_IWGRP | S_IXUSR | S_IRUSR | S_IWUSR);
	}
	else if (ENOENT == errno){
		closedir(dir);
		mkdir("./graphs", 0700);
		set_permissions("graphs", S_IXOTH | S_IROTH | S_IWOTH | S_IXGRP | S_IRGRP | S_IWGRP | S_IXUSR | S_IRUSR | S_IWUSR);
	} else
		perror("opendir failed.");

	printf("\tMENU\n");
	printf("Insert command number\n");
	printf(" 1: Show all connections info\n 2: Show short connections list\n 3: Show connections with suspicious jitter variations\n 0: Exit\n");
	int selection = -1;
	selection = get_int_input();
	while(selection != 0){

		switch(selection){
			case 1:
					detailed_streams_print();
					break;
			case 2:
					short_streams_print();
					break;
			case 3:
					suspicious_streams_print();
					break;
			default :
					printf("You typed an invalid command. Please insert 1, 2 or 3.\n");
				  break;
		}
		printf("\tMENU\n");
		printf("Insert command number\n");
		printf(" 1: Show all connections info\n 2: Show short connections list\n 3: Show connections with suspicious jitter variations\n 0: Exit\n");
		selection = get_int_input();
	}
	return;
}

void detailed_streams_print(){
	int selection = -1;
	print_map();
	printf("\n\tMENU/CONNECTIONS INFO\n 1: Show short connections list\n 2: Draw graph\n 3: Go back\n");
	selection = get_int_input();
	while(selection != 3){

		switch(selection){
			case 1:
					short_streams_print();
					return;
					break;
			case 2:
					draw_stream(0);
					break;
			case 3:
					return;
					break;
			default :
					printf("You typed an invalid command. Please insert 1, 2 or 3.\n");
					break;
		}
		printf("\n\tMENU/CONNECTIONS INFO\n 1: Show short connections list\n 2: Draw graph\n 3: Go back\n");
		selection = get_int_input();
	}
	return;
}

void short_streams_print(){
	int selection = -1;
	print_short_map();
	printf("\n\tMENU/CONNECTIONS LIST\n 1: Show all connections info\n 2: Draw graphs\n 3: Go back\n");
	selection = get_int_input();
	while(selection != 3){

		switch(selection){
			case 1:
					detailed_streams_print();
					return;
					break;
			case 2:
					draw_stream(0);
					break;
			case 3:
					return;
					break;
			default :
					printf("You typed an invalid command. Please insert 1, 2 or 3.\n");
					break;
		}
		printf("\n\tMENU/CONNECTIONS LIST\n 1: Show all connections info\n 2: Draw graphs\n 3: Go back\n");
		selection = get_int_input();
	}
	return;
}

void suspicious_streams_print(){
	int selection = -1;
	print_anomaly_list();
	printf("\n\tMENU/SUSPICIOUS CONNECTIONS\n 1: Draw graph\n 2: Go back\n");
	selection = get_int_input();
	while(selection != 2){

		switch(selection){
			case 1:
					draw_stream(1);
					break;
			case 2:
					return;
					break;
			default :
					printf("You typed an invalid command. Please insert 1 or 2.\n");
					break;
		}
		printf("\n\tMENU/SUSPICIOUS CONNECTIONS\n 1: Draw graph\n 2: Go back\n");
		selection = get_int_input();
	}
	return;
}

//Returns the stream on the <index> position.
//<flag> = { 1  => count only suspicious connections.
//				 { 0  => count all connections.
tcp_stream *stream_lookup(int index, int flag){
	tcp_stream *tmp;
	int i, j = 0;
	for(i = 0; i < SIZE; i++){
		tmp = &streams_map[i];
		while(tmp != NULL){
			if(tmp->stream_name != NULL){
				j++;
				if(flag == 1 && tmp->anomaly == 0)
					j--;
				if(j == index)
					return tmp;
			}
			tmp = tmp->next_conflict;
		}
	}
	return NULL;
}

//Returns an array containing all jitter values in the <str> communication.
double *get_stream_values(tcp_stream *str){
		double *array = malloc(sizeof(double) * str->pkts_num);
		record *tmp = str->head;
		int i = str->pkts_num - 1;
		while( tmp != NULL && i > -1){
			array[i] = (double) tmp->jitter;
			tmp = tmp->next;
			i--;
		}
		return array;
}

int ask_to_save(){
	int flag;
	printf("Do you want to save the communication's graph? [y/n]\n");
	char *save_msg = malloc(sizeof(char) * 16);
	scanf(" %s", save_msg);
	if(strcmp(save_msg, "yes") == 0 || strcmp(save_msg, "y") == 0)
		flag = 1;
	else if(strcmp(save_msg, "no") == 0 || strcmp(save_msg, "n") == 0)
		flag = 0;
	else {
		while(strcmp(save_msg, "yes") != 0 && strcmp(save_msg, "y") != 0 && strcmp(save_msg, "no") != 0 && strcmp(save_msg, "n") != 0){
			printf("Invalid answer, do you want to save the file? [y/n]");
			scanf(" %s", save_msg);
		}
		if(save_msg[0] == 'y')
			flag = 1;
		else
			flag = 0;
	}
	free(save_msg);
	return flag;
}

void draw_stream(int flag){
		int index, save_flag;
		if(flag && anomaly_streams_counter == 0){
			printf("No streams to draw!\n");
			return;
		}
		else if(flag == 0 && streams_number == 0) {
			printf("No streams to draw!\n");
			return;
		}

		printf("Insert connection number of the stream you want to view\n");
		index = get_int_input();
		if(flag != 1){
			while(index < 1 || index > streams_number){
				printf("Invalid connection number. Please insert valid index (1 <= index <= %d) or 0 to go back.\n", streams_number);
				index = get_int_input();
				if(index == 0)
					return;
			}
		}
		else {
			while(index < 1 || index > anomaly_streams_counter){
				printf("Invalid connection number. Please insert valid index (1 <= index <= %d) or 0 to go back.\n", anomaly_streams_counter);
				index = get_int_input();
				if(index == 0)
					return;
			}
		}

    FILE *f;
    char aux[121];
    gnuplot_ctrl * h;
	tcp_stream *stream_to_draw;
    h = gnuplot_init();

	if( (stream_to_draw = stream_lookup(index, flag)) == NULL){
		perror("Fatal error stream_lookup failed!");
		exit(EXIT_FAILURE);
	}

	if(stream_to_draw->pkts_num < 3){
		printf("This connection has too few recorded packets to draw a usefull graph!\n");
		draw_stream(flag);
		return;
	}

	save_flag = ask_to_save();

	double *data = get_stream_values(stream_to_draw);


  	gnuplot_setstyle(h, "lines");
	gnuplot_cmd(h, "set xrange [1:]");
	gnuplot_cmd(h, "set xtics 1");
    gnuplot_cmd(h, "set term x11 persist");

    gnuplot_set_xlabel(h, "# packets");
    gnuplot_set_ylabel(h, "Jitter (ms)");
    gnuplot_plot_x(h, data, stream_to_draw->pkts_num, stream_to_draw->stream_name);
	gnuplot_close(h);

	if( save_flag ){
		h = gnuplot_init();
		gnuplot_setstyle(h, "lines");
		gnuplot_cmd(h, "set xrange [1:]");
		gnuplot_cmd(h, "set xtics 1");

    	gnuplot_set_xlabel(h, "# packets");
    	gnuplot_set_ylabel(h, "Jitter (ms)");

		gnuplot_cmd(h, "set terminal png size 800,600");
		sprintf(aux, "set output './graphs/%s.png'", stream_to_draw->stream_name);
		gnuplot_cmd(h, aux);
		gnuplot_plot_x(h, data, stream_to_draw->pkts_num, stream_to_draw->stream_name);
		sprintf(aux, "./graphs/%s.png", stream_to_draw->stream_name);
		f = fopen (aux,"w");
		set_permissions(aux, S_IXOTH | S_IROTH | S_IWOTH | S_IXGRP | S_IRGRP | S_IWGRP | S_IXUSR | S_IRUSR | S_IWUSR);
		fclose(f);
		gnuplot_close(h);
	}
	free(data);
	return;
}
