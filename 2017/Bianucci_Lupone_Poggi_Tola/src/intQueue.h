#ifndef INT_QUEUE_H_
#define INT_QUEUE_H_
#include <stdbool.h>
#include <stdint.h>

#define SIZE_INT 256

typedef struct intQueue {
  int intQ[SIZE_INT]; 
  unsigned int headID;
  unsigned int tailID;
} queueI_t;

int        	getInt (queueI_t* q); // if empty return 0
int       	putInt (queueI_t* q, int el); // if full return 0

#endif /* INT_QUEUE_H_ */
