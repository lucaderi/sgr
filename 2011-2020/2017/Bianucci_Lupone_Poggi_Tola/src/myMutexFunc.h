/* 
   File:            myMutexFunc.c
   Specifica:       Funzioni utili di uso generico controllo errore 
                    mutex-incapsulati 
*/

#ifndef MYMUTEXFUNC_H
#define MYMUTEXFUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <pthread.h>

extern int Pthread_mutex_lock(pthread_mutex_t *mtx);
extern int Pthread_mutex_unlock(pthread_mutex_t *mtx);
extern int Pthread_cond_signal(pthread_cond_t *cond);
extern int Pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mtx);

#endif
