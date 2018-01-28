#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hash-table.h"

int mypcap_hashtable_init( struct mypcap_hashtable *hashtable , size_t slots )
{
    hashtable->slot_array = calloc( hashtable->slots = slots ,
                                    sizeof( struct mypcap_hashtable_node * ) );

    return hashtable->slot_array == NULL;
}

uint32_t mypcap_hashtable_hash( struct mypcap_hashtable *hashtable ,
                                struct mypcap_flow_key *key )
/* TODO: Migliorare? */
{
    return ( key->src.ip.s_addr ^
             key->dst.ip.s_addr ^
             ( key->src.port | ( key->dst.port << 16 ) ) ) % hashtable->slots;
}

int mypcap_hashtable_update( struct mypcap_hashtable *hashtable ,
                             struct mypcap_flow_update_info *update_info )
{
    struct mypcap_hashtable_node **slot_p , *first_free = NULL;

    /* va allo slot */
    slot_p = &hashtable->slot_array[ update_info->hash ];

    /* scorre  */
    /* TODO: Evitare la crescita eliminando ogni tanto quelli
       inutilizzati? */
    while ( *slot_p &&                                      /* fino alla fine della lista */
            memcmp( &( *slot_p )->key , &update_info->key ,
                    sizeof( struct mypcap_flow_key ) ) )    /* o fino a che non trova l'elemento corrispondente */
    {
        /* salva il primo elemento vuoto che incontra */
        if ( !first_free && !( *slot_p )->used )
        {
            first_free = *slot_p;
        }

        slot_p = &( *slot_p )->next;                        /* va al successivo elemento */
    }

    /* se va aggiornato un elemento (trovato!) */
    if ( *slot_p )
    {
        /* se e' un flusso ancora valido */
        if ( ( *slot_p )->used )
        {
            /* (!)  se a questo punto (o immediatamente prima di
               aggiornare il flag used) il thread dumper stampa il
               flusso e cambia il flag a 0 questo flusso durera' piu'
               del normale e alla sua terminazione ci sara' piu di una
               stampa che lo riguarda, ma dato che vengono mostrati
               anche i timestamp (primo e ultimo) ogni stampa
               corrisponde a verita'; se invece cio' accade tra i
               successivi 3 statement la prima stampa risultera'
               parzialmente errata. */

            /* lo aggiorna */
            ( *slot_p )->data.pkts++;
            ( *slot_p )->data.bytes += update_info->bytes;
            ( *slot_p )->data.lst = update_info->lst;
        }
        /* altrimenti */
        else
        {
            /* lo resetta */
            ( *slot_p )->data.pkts = 1;
            ( *slot_p )->data.bytes = update_info->bytes;
            ( *slot_p )->data.fst = ( *slot_p )->data.lst = update_info->lst;
        }

        /* aggiorna il flag */
        ( *slot_p )->used = 1; /* per ultimo */
    }
    /* se va inserito un nuovo elemento */
    else
    {
        struct mypcap_hashtable_node *new_node;

        /* se esiste un elemento libero nello slot */
        if ( first_free )
        {
            new_node = first_free;
        }
        /* se va allocato */
        else
        {
            /* alloca l'elemento */
            new_node = calloc( 1 , sizeof( struct mypcap_hashtable_node ) );
            if ( !new_node ) return 0;            /* ENOMEM */

            /* inizializza l'elemento */
            new_node->next = NULL;
        }

        /* inizializza l'elemento */
        new_node->key = update_info->key;
        new_node->data.pkts = 1;
        new_node->data.bytes = update_info->bytes;
        new_node->data.fst = new_node->data.lst = update_info->lst;
        new_node->used = 1; /* per ultimo */

        /* se l'elemento e' stato allocato; lo inserisce nella lista */
        if ( !first_free ) *slot_p = new_node;
    }

    return 1;
}

void mypcap_hashtable_free( struct mypcap_hashtable *hashtable )
{
    if ( hashtable )
    {
        size_t i;

        /* scorre gli slot */
        for ( i = 0 ; i < hashtable->slots ; i++ )
        {
            struct mypcap_hashtable_node *ptr;

            /* scorre la lista */
            for ( ptr = hashtable->slot_array[ i ] ; ptr ; )
            {
                struct mypcap_hashtable_node *aux;

                /* dealloca l'elemento e va al successivo */
                aux = ptr;
                ptr = ptr->next;
                free( aux );
            }
        }

        /* dealloca gli slot */
        free( hashtable->slot_array );
    }
}

