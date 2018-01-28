#ifndef CEMETERY_H_
#define CEMETERY_H_

#include "hashtable.h"

#define FIRST 1597 /* 18th Fibonacci number (0, 1, 1, 2, ...) */
#define SECOND 2584 /* 19th Fibonacci number (0, 1, 1, 2, ...) */

/*#define FIRST 0  18th Fibonacci number (0, 1, 1, 2, ...) */
/*#define SECOND 1  19th Fibonacci number (0, 1, 1, 2, ...) */

/* A dinamically growing data structure, whose growth is
 * as the Fibonacci numbers growth.
 * It is a Linked List of arrays holding pointers to expired flows
 * whose memory has to be freed.
 * The size of an array in the list, results from the sum of the sizes
 * of the previous two arrays in the list.
 * */
typedef struct cemetery
{
	unsigned int fibN; /* the size of the last array in the list */
	unsigned int fibNminus1; /* the size of the last but one array in the list */
	unsigned int last; /* the first free position in the last not empty array */
	unsigned int lastNotEmptyLen; /* the size of the last not empty array in the list */
	unsigned int prevBlockLen; /* the size of the last but one not empty array in the list */
	t_hashEntry **lastNotEmpty; /* the last not empty array in the list */
	t_hashEntry **first; /* the first array in the list */
} t_cemetery;

t_cemetery *createCemetery();
/* adds a flow to the cemetery, allocating new memory if needed */
void addToCemetery(t_cemetery *cemetery, const t_hashEntry *entry);
/* frees the memory used by the flows holded, leaving the cemetery size unaltered,
 * after this function returns, the cemetery results empty */
unsigned int freeCemetery(t_cemetery *cemetery);

#endif /* CEMETERY_H_ */
