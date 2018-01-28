/* 
   File:            myMutexFunc.c
   Specifica:       Funzioni utili di uso generico controllo errore 
                    mutex-incapsulati 
*/

#include "myMutexFunc.h"

int Pthread_mutex_lock(pthread_mutex_t *mtx);
int Pthread_mutex_unlock(pthread_mutex_t *mtx);

/*******************************************************
Func body
********************************************************/

/*-------------------------------------------------*/
int Pthread_mutex_lock(pthread_mutex_t *mtx)
{
  int err = 0;
  if ((err = pthread_mutex_lock(mtx)) != 0)
  {
    errno = err;
    perror("mutex lock");
    pthread_exit(&errno);
  }
  return err;
}

/*----------------------------------------------------------------*/
int Pthread_mutex_unlock(pthread_mutex_t *mtx)
{
  int err = 0;
  if ((err = pthread_mutex_unlock(mtx)) != 0)
  {
    errno = err;
    perror("mutex unlock");
    pthread_exit(&errno);
  }
  return err;
}

/*-------------------------------------------------*/
int Pthread_cond_signal(pthread_cond_t *cond)
{
  int err = 0;
  if ((err = pthread_cond_signal(cond)) != 0)
  {
    errno = err;
    perror("signal");
    pthread_exit(&errno);
  }
  return err;
}
/*----------------------------------------------------------------*/
int Pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mtx)
{
  int err = 0;
  if ((err = pthread_cond_wait(cond, mtx)) != 0)
  {
    errno = err;
    perror("cond wait");
    pthread_exit(&errno);
  }
  return err;
}
