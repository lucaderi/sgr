#include "time_tools.h"
#include <time.h>
#include <stdio.h>
#define TO_NANO(n) n * 1000000

//Metodo che restiuisce una struct timespec contenente l' ammontare di millis millisecondi.
struct timespec get_timespec(int millis){
  struct timespec sleep_time;
  if(millis < 0){
    fprintf(stderr,"Negative millis amount.");
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 0;
    return sleep_time;
  }
  sleep_time.tv_sec = millis / 1000;
  sleep_time.tv_nsec = TO_NANO(millis % 1000);
  return sleep_time;
}

//Metodo che restituisce una struct timespec aggiornata all' orario corrente.
struct timespec update_timespec(){
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return now;
}

//Metodo che restituisce, in millisecondi, la differenza di tempo tra due struct timespec.
long int get_elapsed_time(struct timespec start, struct timespec end){
  long int seconds_in_millis =  (end.tv_sec - start.tv_sec) * 1000;
  long int nseconds_in_millis = (end.tv_nsec - start.tv_nsec) / 1000000;
  return seconds_in_millis + nseconds_in_millis;
}

long int timespec_to_millis(struct timespec time){
	long int seconds_in_millis = time.tv_sec * 1000;
	long int nseconds_in_millis   = time.tv_nsec / 1000000;
	return seconds_in_millis + nseconds_in_millis;
}
