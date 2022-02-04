/**
  *	file: queue.h
  *	Autore: Gabriele Ceccarini 523788, Andrea Poggi 524865
  *	progetto SISTEMI OPERATIVI, secondo frammento
  *	
  *	si dichiara che il contenuto di questo file è in ogni sua parte
  *	opera originale dell' autore.
  */

#ifndef QUEUE_H_
#define QUEUE_H_
#include <stdbool.h>
/**
 * @struct queue elem
 * @brief elemento coda 
 *
 * @var el campo della coda con informazione
 * @var next puntatore al successivo
 */

typedef struct queueElem
{

    void *el;
    struct queueElem *next;

} queueElem_t;

/**
 * @struct connection queue
 * @brief coda connessioni
 *
 * @var head puntatore testa
 * @var tail puntatore alla coda
 */

typedef struct Queue
{

    queueElem_t *head;
    queueElem_t *tail;

} queue_t;

/**
 * @function createQueue
 * @brief crea una coda vuota
 *
 * @return NULL se fallisce, puntatore alla coda altrimenti
 */
queue_t *createQueue();

/**
 * @function add element
 * @brief aggiunge un elemento in coda
 *
 * @param fd_c file descriptor
 * @param queue puntatore alla coda
 *
 * @return -1 se fallisce 0 altrimenti
 */
int addQueueElem(void *el, queue_t *queue, pthread_mutex_t *mtx, pthread_cond_t *cond);

/**
 * @function get head
 * @brief restituisce primo elemento
 *
 * @param queue puntatore alla coda
 *
 * @return -1 se la coda è vuota, un file descriptor altrimenti
 */
void *getHead(queue_t *queue, pthread_mutex_t *mtx, pthread_cond_t *cond);

/**
 * @function remove element (PRIVATE!!!)
 * @brief rimuove elemento in testa alla coda
 *
 * @param queue puntatore alla coda
 */
void removeQueueElem(queue_t *queue);

/**
 * @function isEmptyQueue (PRIVATE!!!)
 * @brief controlla se la coda è vuota
 *
 * @param queue puntatore alla coda
 *
 * @return true se è vuota false altrimenti
 */
bool isEmptyQueue(queue_t *queue);

/**
 * @function deleteQueue
 * @brief dealloca la coda
 *
 * @param queue puntatore alla coda da deallocare
 *
 * @return -1 se fallisce 0 altrimenti
 */
void deleteQueue(queue_t *queue, pthread_mutex_t *mtx);

#endif /* QUEUE_H_ */
