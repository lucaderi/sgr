#ifndef ARRAYQUEUE_H_
#define ARRAYQUEUE_H_

#include "pkt_info.h"

typedef struct arrayqueue
{
	int size;
	int enq;
	int deq;
	t_pkt_info *queue;
} t_pkt_queue;

t_pkt_queue *createQueue(int size);
void enqueue(t_pkt_queue *queue, t_pkt_info *pkt);
t_pkt_info *dequeue(t_pkt_queue *queue);

#endif /* ARRAYQUEUE_H_ */
