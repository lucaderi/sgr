#ifndef _UTILS_H
#define _UTILS_H
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>

#ifdef linux
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#endif

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <libkern/OSAtomic.h>
#endif

#define FALSE 0
#define TRUE -1

#define BUFLEN 128
#define MALLOC(var, size, ret)	if (!((var) = malloc((size)))) { errno = ENOMEM; perror(NULL); return (ret);}
#define CALLOC(var, count, size, ret)	if (!((var) = calloc((count),(size)))) { errno = ENOMEM; perror(NULL); return (ret);}

/*
 Let the user interactively choose an interface.
 Returns the name of the choosen interface.
 Returns NULL on error (eg. no interfaces available).
 */
char* selectInterface(int verbose);

/*
 If current user is root try changing user to nobody
 */
void changeUser();

/*
 Returns header offset from datalink id.
 If datalink is not recognized returns -1.
 */
int datalinktooffset(int dl_id);

/*
 Copy the physical addres for the device named dev_name into
 the memory portion pointed by mac (assumed to be at least 6 byte long)
 On success returns 0.
 */
int get_mac_addr(char *dev_name , u_char *mac);

/* Atomic spin lock funtions */
#ifdef linux
#define spinlock_t pthread_spinlock_t
#define SPINLOCK_BUSY EBUSY
#define spinlock_lock(LOCK) pthread_spin_lock((LOCK)) /*int*/
#define spinlock_trylock(LOCK) pthread_spin_trylock((LOCK)) /*int*/
#define spinlock_unlock(LOCK) pthread_spin_unlock((LOCK)) /*int*/
#endif

#ifdef __APPLE__
#define spinlock_t OSSpinLock
#define SPINLOCK_BUSY false
#define spinlock_lock(LOCK) OSSpinLockLock((LOCK)) /*void*/
#define spinlock_trylock(LOCK) OSSpinLockTry((LOCK)) /*bool*/
#define spinlock_unlock(LOCK) OSSpinLockUnlock((LOCK)) /*void*/
#endif

/* Initialize a spinlock. On success returns 0 */
int create_spinlock(spinlock_t * lock);
/* Destroy a spinlock. On success returns 0*/
int destroy_spinlock(spinlock_t * lock);
#endif
