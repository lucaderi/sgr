#include <cstdio>

#include "timeUtil.h"

void print_timeval(timeval * tv){
  printf("TV_SEC : %li , TV_USEC : %li\n", tv->tv_sec, tv->tv_usec);
  printf("WHEN : %li\n", tv->tv_sec + (tv->tv_usec / 1000));
}
