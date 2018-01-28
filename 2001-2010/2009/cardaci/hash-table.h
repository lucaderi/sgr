#ifndef __MYPCAP_HASHTABLE_H__
#define __MYPCAP_HASHTABLE_H__

#include "flow.h"

/* elemento della tabella hash */
struct mypcap_hashtable_node
{
    struct mypcap_flow_key key;         /* identificatore del flusso */
    struct mypcap_flow_data data;       /* dati del flusso  */
    unsigned int used:1;                /* flag di utilizzo per questo nodo */
    struct mypcap_hashtable_node *next; /* puntatore al prossimo nodo */
};

/* tabella hash */
struct mypcap_hashtable
{
    struct mypcap_hashtable_node **slot_array;
    size_t slots;                                 /* numero di slot (liste) */
};

/* inizializza la tabella hash; restituisce 1 in caso di successo, 0
   altrimenti */
int mypcap_hashtable_init( struct mypcap_hashtable *hashtable ,
                           size_t slots );

/* calcola l'hash della chiave passata */
uint32_t mypcap_hashtable_hash( struct mypcap_hashtable *hashtable ,
                                struct mypcap_flow_key *key );

/* aggiorna la tabella hash con le informazioni passate; restituisce 1
   in caso di successo, 0 altrimenti (ENOMEM) */
int mypcap_hashtable_update( struct mypcap_hashtable *hashtable ,
                             struct mypcap_flow_update_info *update_info );

/* libera la memoria occupata dalla tabella hash */
void mypcap_hashtable_free( struct mypcap_hashtable *hashtable );

#endif
