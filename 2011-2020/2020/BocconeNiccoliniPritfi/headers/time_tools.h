#ifndef time_tools_h
#define time_tools_h

#include <time.h>
#include <stdio.h>

extern struct timespec get_timespec(int millis);
extern struct timespec update_timespec();
extern long int get_elapsed_time(struct timespec start, struct timespec end);
extern long int timespec_to_millis(struct timespec time);

#endif
