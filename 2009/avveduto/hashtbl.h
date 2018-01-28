/*
 * hashtbl.h
 *      Author: Giovanni Avveduto
 *      SGR Exercise
 */

#include <stdlib.h>
#include "AvvedutoSniffer.h"

typedef size_t hash_size;

struct hashnode_s {
	struct flow_bidir *data;
	struct hashnode_s *next;
};

struct dead_hashnode{
	struct hashnode_s *node;
	struct dead_hashnode *next;
};

typedef struct hashtbl {
	hash_size size;
	struct hashnode_s **nodes;
} HASHTBL;


HASHTBL *hashtbl_create(hash_size size);
void hashtbl_destroy(HASHTBL *hashtbl);
int hashtbl_insert(HASHTBL *hashtbl, struct queue_elem *data);
struct dead_hashnode *hashtbl_remove(HASHTBL *hashtbl, int flow_lifetime,int flow_timeout, struct dead_hashnode **exp_flows);
