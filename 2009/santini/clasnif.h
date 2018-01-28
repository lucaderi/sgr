/*
 * clasnif.h
 * Author: Claudio Santini (santinic@cli.di.unip.it)
 */

#ifndef CLASNIF_H_
#define CLASNIF_H_

#include <time.h>
#include <netinet/tcp.h>
#include "uthash.h"

/* Key for the hashmap */
typedef struct {
	struct in_addr src;
	struct in_addr dst;
	u_int16_t src_port;
	u_int16_t dst_port;
} hashkey_t;

/* A list to store the good packets */
typedef struct {
	u_char * buf;
	u_char * start; 			/* for a correct free() */
	int size;
	struct list_t * next;
} list_t;

/*
 * A generic connection with a buffer to store sniffed packets.
 * src, dest, srcp and destp are together key for the hashtable.
 */
typedef struct {
	hashkey_t key;
	time_t time;				/* last edit time */
	list_t * head;
    UT_hash_handle hh;			/* makes this structure hashable */
} conn_t;

#endif /* CLASNIF_H_ */
