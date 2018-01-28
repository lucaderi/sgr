#ifndef __FLOW_QUEUE_H
#define __FLOW_QUEUE_H

#include "flow.h"

#define N 2048

typedef struct struct_element {
	unsigned int hash_key;
	flow* f;
} element;

/* circular queue */
typedef struct struct_queue {
	element* content[N];
	int front, rear;
	int size;
} queue;

void flow_queue_init(queue*);
int flow_queue_insert(queue*, element**);
element* flow_queue_remove(queue*);

#endif
