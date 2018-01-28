/**
  *	file: queue.c
  *	Autore: Gabriele Ceccarini 523788, Andrea Poggi 524865
  *	progetto SISTEMI OPERATIVI, secondo frammento
  *	
  *	si dichiara che il contenuto di questo file è in ogni sua parte
  *	opera originale dell' autore.
  */

#include <stdlib.h>
#include <stdio.h>
#include "queue.h"
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "myMutexFunc.h"

queue_t *createQueue()
{

    queue_t *aus = malloc(sizeof(queue_t));
    if (!aus)
        return NULL;

    aus->head = NULL;
    aus->tail = NULL;

    return aus;
}

int addQueueElem(void *el, queue_t *queue, pthread_mutex_t *mtx, pthread_cond_t *cond)
{
    queueElem_t *aus = malloc(sizeof(queueElem_t));
    if (!aus)
        return -1;
    aus->el = el;
    aus->next = NULL;
    Pthread_mutex_lock(mtx);
    if (isEmptyQueue(queue))
    {
        queue->head = aus;
        queue->tail = aus;
    }
    else
    {
        queue->tail->next = aus;
        queue->tail = aus;
    }
    if (cond != NULL)
        pthread_cond_signal(cond);
    Pthread_mutex_unlock(mtx);
    return 0;
}

void *getHead(queue_t *queue, pthread_mutex_t *mtx, pthread_cond_t *cond)
{
    Pthread_mutex_lock(mtx);
    if (cond != NULL)
    {
        //printf("cond != NULL\n");
        while (isEmptyQueue(queue))
            pthread_cond_wait(cond, mtx);
    }
    else
    {
        //printf("cond == NULL\n");
        if (isEmptyQueue(queue))
        {
            Pthread_mutex_unlock(mtx);
            return NULL;
        }
    }
    void *result = queue->head->el;
    removeQueueElem(queue);
    Pthread_mutex_unlock(mtx);
    return result;
}

void removeQueueElem(queue_t *queue)
{

    if (queue->head == queue->tail)
    {
        free(queue->head);
        queue->head = NULL;
        queue->tail = NULL;
    }
    else
    {
        queueElem_t *curr;
        curr = queue->head;
        queue->head = queue->head->next;
        free(curr);
    }
}

bool isEmptyQueue(queue_t *queue)
{

    if (queue->head == NULL)
        return true;
    else
        return false;
}

void deleteQueue(queue_t *queue, pthread_mutex_t *mtx)
{
    queueElem_t *curr;
    Pthread_mutex_lock(mtx);
    if (queue != NULL)
    {

        while (queue->head != NULL)
        {
            free(curr->el);
            curr = queue->head;
            queue->head = queue->head->next;
            free(curr);
        }
        free(queue);
    }
    Pthread_mutex_unlock(mtx);
}
