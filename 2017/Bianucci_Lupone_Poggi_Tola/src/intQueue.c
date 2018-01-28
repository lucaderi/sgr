#include <stdlib.h>
#include <stdio.h>
#include "intQueue.h"

int getInt(queueI_t *q) //return 0 if is empty, next element if sucessfull
{
  if (q->headID == q->tailID)
    return 0;

  int result = q->intQ[q->tailID];
  q->tailID = (q->tailID + 1) % SIZE_INT;

  return result;
}

int putInt(queueI_t *q, int el) //return 0 if Full, 1 if OK
{
  if (((q->headID + 1) % SIZE_INT) == q->tailID)
    return 0;
  else
  {
    q->intQ[q->headID] = el;
    q->headID = (q->headID + 1) % SIZE_INT;
  }
  return 1;
}
