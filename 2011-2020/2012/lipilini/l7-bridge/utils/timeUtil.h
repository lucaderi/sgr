#ifndef _TIMEUTIL_H
#define _TIMEUTIL_H

#include <netinet/in.h>
#include <ctime>

static __inline__ bool is_greater_timeval(timeval * t1, timeval * t2){
  return((t1->tv_sec > t2->tv_sec) || (t1->tv_sec == t2->tv_sec && t1->tv_usec > t2->tv_usec));
}

void print_timeval(timeval * tv);

static __inline__ u_int64_t rdtsc(){
  unsigned hi, lo;
  //asm("cpuid"); // serialization
  asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (u_int64_t)lo)|( ((u_int64_t)hi)<<32 );
}

#endif // _TIMEUTIL_H
