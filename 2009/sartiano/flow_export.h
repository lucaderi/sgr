#ifndef __FLOW_EXPORT_H
#define __FLOW_EXPORT_H

#include <pthread.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "flow.h"
#include "hashtable.h"


#define TIME_TO_EXPORT 60
#define DIM_BUFFER 1024

typedef struct struct_queue_city_info {
	char* buffer[DIM_BUFFER];
	int front;
	int rear;
    int size;
} queue_city_info;


void queue_init(queue_city_info*);
int queue_insert(queue_city_info*, char*);
char* queue_remove(queue_city_info*);
int flow_export(struct hashtable*, pthread_mutex_t*, GeoIP*);
int flow_export_time(flow *);

#endif
