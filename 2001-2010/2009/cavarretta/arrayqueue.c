#include "arrayqueue.h"
#include <stdlib.h>
#include <stdio.h>

t_pkt_queue *createQueue(int size)
{
	t_pkt_queue *queue = malloc(sizeof(t_pkt_queue));
	if (!queue)
	{
		fprintf(stderr,"createQueue: Impossibile allocare memoria.\n");
		return NULL;
	}
	queue->queue = malloc(size * sizeof(t_pkt_info));
	if (!queue->queue)
	{
		fprintf(stderr,"createQueue: Impossibile allocare memoria.\n");
		free(queue);
		return NULL;
	}
	queue->size = size;
	queue->enq = 0;
	queue->deq = size - 1;
	return queue;
}

void enqueue(t_pkt_queue *queue, t_pkt_info *pkt)
{
	/*while (1)*/
		if((queue->enq + 1) % queue->size != queue->deq)
		{
			queue->queue[queue->enq] = *pkt;
			queue->enq = (queue->enq + 1) % queue->size;
			/*break;*/
		}
}

t_pkt_info *dequeue(t_pkt_queue *queue)
{
	queue->deq = (queue->deq + 1) % queue->size;
	while(1)
		if(queue->deq != queue->enq)
			return &(queue->queue[queue->deq]);
}
