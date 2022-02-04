#include <stdlib.h>

#include "types.h"
#include "timeUtils.h"

usec_t usec_timevalsub(struct timeval *t1, struct timeval *t2) {
  struct timeval result;
  timersub(t1, t2, &result);
  return timeval2usec(&result);
}

usec_t usec_timeval_abs_sub(struct timeval *t1, struct timeval *t2) {
  struct timeval result;
  if (timercmp(t1, t2, >=)) 
    timersub(t1, t2, &result);
  else
    timersub(t2, t1, &result);
  return timeval2usec(&result);
}

double msec_timevalsub(struct timeval *t1, struct timeval *t2) {
  struct timeval result;
  timersub(t1, t2, &result);
  return timeval2msec(&result);
}
