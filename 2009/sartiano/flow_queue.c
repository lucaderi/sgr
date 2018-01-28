#include "flow_queue.h"

void flow_queue_init(queue* q) {
	q->front = 0;
	q->rear = 0;
	q->size = 0;
}

int flow_queue_insert(queue* q, element **e) {
	int index = (q->rear + 1) % N;
	if (index == q->front) {
		return 1;
	}
	q->rear = index;
	q->content[index] = *e;
	q->size++;
	return 0;
}

element* flow_queue_remove(queue* q) {
	if (q->front == q->rear) {
		return NULL;
	}
	q->front = (q->front + 1) % N;
	q->size--;
	return (q->content[q->front]);
}
