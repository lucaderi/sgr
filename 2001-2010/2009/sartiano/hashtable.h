/*
 * hashtable.h
 *
 *  Created on: Jun 28, 2009
 *      Author: lele
 */

#ifndef HASHTABLE_H_
#define HASHTABLE_H_

#include "flow.h"
#include <pthread.h>

#define INIT_SIZE 65536 //2^16


struct entry {
	flow *f;
	struct entry *next;
};

struct hashtable {
	int number_entry;
	int size;
	struct entry **table;
};

struct hashtable* create_hashtable(void);
unsigned int hashtable_hash(flow_key*);
struct entry* hashtable_search(struct hashtable *, int, flow *);
struct hashtable* hashtable_insert(struct hashtable *, flow *, pthread_mutex_t*);
void hashtable_delete(struct hashtable *);


#endif /* HASHTABLE_H_ */
