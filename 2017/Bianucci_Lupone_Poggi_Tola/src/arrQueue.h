#ifndef ARR_QUEUE_H_
#define ARR_QUEUE_H_
#include <stdbool.h>
#include <stdint.h>

#define SIZE 2000

typedef struct arrQueueElem
{
  uint8_t direction; // 0= in; 1= out
  int Port;          // myport
  u_char Protocol;
  unsigned int byteLen;
} arrQueueElem_t;

typedef struct arrQueue
{
  arrQueueElem_t arrQ[SIZE];
  unsigned int headID;
  unsigned int tailID;
} queueA_t;

int getArrQueueElem(queueA_t *q, arrQueueElem_t *elem); // return 0 if is empty, 1 if sucessfull
int putArrQueueElem(queueA_t *q, arrQueueElem_t *elem); // return 0 if Full, 1 if OK

#endif /* ARR_QUEUE_H_ */
