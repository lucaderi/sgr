#include "flow.h"
#include "pkt_info.h"
#include <stdio.h>

#define HASH_FAIL 2
#define NULL_PTR 1

typedef t_flow_ID t_key;
typedef t_flow_info t_value;

typedef struct hashE
{
	t_key key;
    t_value value;
    struct hashE *next;
} t_hashEntry;

typedef struct ListHead
{
	pthread_spinlock_t busy;
	t_hashEntry *first;
} t_list_head;

typedef struct
{
    int size;    /* ampiezza tabella */
    t_list_head *table;
    unsigned int (*hashfunc)(void *);
    char *(*printkey)(const void *);
    char *(*printvalue)(const void *);
    int (*updatevalue)(void *, void *, int);
} t_hashTable;

t_hashTable *createHash(int tableSize, unsigned int (*hashfunc)(void *), int (*updatevalue)(void *, void *, int), char *(*printkey)(const void *), char *(*printvalue)(const void *));

void deleteHash(t_hashTable *ht);

int hashFunction (const t_pkt_info *key, t_hashTable *ht);

t_hashEntry *updateHashEntry(t_hashTable *ht, const t_pkt_info *key);

int printHashEntry (FILE *uscita, t_hashTable *ht, t_hashEntry *e);

int printHashTable (FILE *uscita, t_hashTable *t);

void deleteHashElement (t_hashEntry *e);
