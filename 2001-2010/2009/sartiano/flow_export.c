/*
 * flow_export.c
 *
 *  Created on: Jun 10, 2009
 *      Author: lele
 */

#include "daniele_sartiano.h"

#include <sys/time.h>
#include <assert.h>

void queue_init(queue_city_info* q) {
	q->front = 0;
	q->rear = 0;
	q->size = 0;
}

int queue_insert(queue_city_info* q, char* s) {
	if (s == NULL)
		return 0;
	int index = (q->rear + 1) % DIM_BUFFER;
	if (index == q->front) {
		return 1;
	}
	q->rear = index;
	q->buffer[index] = s;
	q->size++;
	return 0;
}

char* queue_remove(queue_city_info* q) {
	if (q->front == q->rear) {
		return NULL;
	}
	q->front = (q->front + 1) % DIM_BUFFER;
	q->size--;
	return (q->buffer[q->front]);
}

int flow_export_time(flow *f) {
	struct timeval now;

	gettimeofday(&now, NULL);

	if ((f->last.tv_sec - f->first.tv_sec) > TIME_TO_EXPORT) {
		return 1;
	}
	if ((now.tv_sec - f->last.tv_sec) > TIME_TO_EXPORT) {
		return 1;
	}

	return 0;

}

int flow_export(struct hashtable *h, pthread_mutex_t *mutex, GeoIP *gi) {
	int i;
	struct entry *e = NULL;
	struct entry *e_next = NULL;
	for (i = 0; i < INIT_SIZE; i++) {
		if (h->table[i] != NULL) {
			e = h->table[i];

			//if is first element in the hash table
			while (e != NULL && flow_export_time(e->f)) {
				pthread_mutex_lock(mutex);
				h->table[i] = h->table[i]->next;
				flow_print_export(e->f);
				page_insert_flow(flow_create_string(e->f));
				if (gi != NULL) {
					pthread_mutex_lock(&mutex_queue_geo);
					queue_insert(&q_city_info, flow_get_geo_info(e->f, gi));
					pthread_mutex_unlock(&mutex_queue_geo);
				}
				free(e->f->key);
				free(e->f);
				free(e);
				h->number_entry--;
				e = h->table[i];
				pthread_mutex_unlock(mutex);
			}

			if (e != NULL) {
				e_next = e->next;
				while (e_next != NULL) {
					if (flow_export_time(e_next->f)) {
						pthread_mutex_lock(mutex);
						e->next = e_next->next;
						flow_print_export(e_next->f);
						page_insert_flow(flow_create_string(e->f));
						if (gi != NULL) {
							pthread_mutex_lock(&mutex_queue_geo);
							queue_insert(&q_city_info, flow_get_geo_info(e->f,
									gi));
							pthread_mutex_unlock(&mutex_queue_geo);
						}
						free(e_next->f->key);
						free(e_next->f);
						free(e_next);
						h->number_entry--;
						e_next = e->next;
						pthread_mutex_unlock(mutex);
					} else {
						e = e_next;
						e_next = e_next->next;
					}
				}
			}
		}
	}
	return h->number_entry;
}

