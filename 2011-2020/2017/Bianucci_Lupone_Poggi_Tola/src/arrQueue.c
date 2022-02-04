#include <stdlib.h>
#include <stdio.h>
#include "arrQueue.h"

int getArrQueueElem(queueA_t *q, arrQueueElem_t *elem) // return 0 if is empty, 1 if sucessfull
{
  if (q->headID == q->tailID)
    return 0;
  elem->direction = q->arrQ[q->tailID].direction;
  elem->Port = q->arrQ[q->tailID].Port;
  elem->Protocol = q->arrQ[q->tailID].Protocol;
  elem->byteLen = q->arrQ[q->tailID].byteLen;
  q->tailID = (q->tailID + 1) % SIZE;
  return 1;
}

int putArrQueueElem(queueA_t *q, arrQueueElem_t *elem) // return 0 if Full, 1 if OK
{
  if (((q->headID + 1) % SIZE) == q->tailID)
    return 0;
  else
  {
    q->arrQ[q->headID].direction = elem->direction;
    q->arrQ[q->headID].Port = elem->Port;
    q->arrQ[q->headID].Protocol = elem->Protocol;
    q->arrQ[q->headID].byteLen = elem->byteLen;
    q->headID = (q->headID + 1) % SIZE;
  }
  return 1;
}
