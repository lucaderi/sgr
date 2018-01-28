#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "hash-table.h"
#include "httpd.h"
#include "flow.h"

extern int mypcap_stop;

/* code circolari dove il thread che cattura metti i pacchetti per
   passarli ai thread che li inseriscono nella tabella hash */
static struct mypcap_flow_update_info mypcap_rr_queues[ MYPCAP_FLOW_THREADS ][ MYPCAP_FLOW_RR_QUEUE_SIZE ];

/* indici di scrittura relativi alle code circolari */
static size_t mypcap_rr_queues_indexes[ MYPCAP_FLOW_THREADS ] = { 0 };

/* variabili di condizione associate alla presenza di pacchetti nelle
   code */
static pthread_cond_t mypcap_rr_queues_cvs[ MYPCAP_FLOW_THREADS ];

/* tabella hash dei flussi */
static struct mypcap_hashtable mypcap_flow_hashtable;

/* id dei thread che aggiornano la tabella */
static pthread_t mypcap_flow_inserters_id[ MYPCAP_FLOW_THREADS ];

/* id del thread che scorre i flussi */
static pthread_t mypcap_flow_dumper_id;

/* thread che aggiorna la tabella hash dei flussi */
static void * mypcap_flow_inserter( void * args )
{
    struct mypcap_flow_update_info *elem_p;
    size_t index , thread_idx;
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    /* puntatore all'elemento */
    elem_p = &mypcap_rr_queues[ thread_idx = ( size_t )args ][ index = 0 ];

    /* lock */
    assert( pthread_mutex_lock( &mtx ) == 0 );

    /* loop */
    while ( !mypcap_stop )
    {
        /* attende che ci siano pacchetti */
        while ( !elem_p->used )
        {
            pthread_cond_wait( &mypcap_rr_queues_cvs[ thread_idx ] , &mtx );

            /* termina se interrotto  */
            if ( mypcap_stop ) return NULL;
        }

        /* aggiorna la tabella */
        if ( !mypcap_hashtable_update( &mypcap_flow_hashtable , elem_p ) )
        {
            fprintf( stderr , "out of memory; dropped\n" );
        }

        /* segna l'elemento della coda come nopn usato */
        elem_p->used = 0; /* per ultimo */

        /* va al successivo */
        index = ( index + 1 ) % MYPCAP_FLOW_RR_QUEUE_SIZE;
        elem_p = &mypcap_rr_queues[ thread_idx ][ index ];
    }

    /* unlock */
    assert( pthread_mutex_unlock( &mtx ) == 0 );

    return NULL;
}

/* thread che scorre i flussi cercando quelli da scartare */
static void * mypcap_flow_dumper( void *args )
{
    size_t httpd = ( size_t )args;

    while ( !mypcap_stop )
    {
        size_t i;

        /* scorre gli slot */
        for ( i = 0 ; i < mypcap_flow_hashtable.slots ; i++ )
        {
            struct mypcap_hashtable_node *ptr;

            /* scorre la lista */
            for ( ptr = mypcap_flow_hashtable.slot_array[ i ] ; ptr ; ptr = ptr->next )
            {
                time_t now = time( NULL );

                /* controlla se il flusso va scartato */
                if ( ptr->used &&
                     ( now - ptr->data.fst > MYPCAP_FLOW_MAX_ACTIVITY_TIME ||        /* attivo da troppo */
                       now - ptr->data.lst > MYPCAP_FLOW_MAX_INACTIVITY_TIME ) )     /* inattivo da troppo */
                {
                    /* se i dati vanno inviati al server http */
                    if ( httpd )
                    {
                        mypcap_httpd_push_flow( &ptr->key , &ptr->data );
                    }
                    /* altrimenti stampati su stdout */
                    else
                    {
                        char ip_src_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };
                        char ip_dst_buf[ INET_ADDRSTRLEN + 1 ] = { 0 };

                        /* converte gli indirizzi IP */
                        inet_ntop( AF_INET , &ptr->key.src.ip , ip_src_buf , INET_ADDRSTRLEN );
                        inet_ntop( AF_INET , &ptr->key.dst.ip , ip_dst_buf , INET_ADDRSTRLEN );

                        /* stampa le informazioni sul flusso */
                        printf( "F %lu - %lu %s:%u -> %s:%u : %u pkts ; %u bytes\n" ,
                                ptr->data.fst , ptr->data.lst ,           /* inizio e fine */
                                ip_src_buf , ptr->key.src.port ,          /* sorgente */
                                ip_dst_buf , ptr->key.dst.port ,          /* destinazione */
                                ptr->data.pkts ,                          /* pacchetti */
                                ptr->data.bytes );                        /* bytes */
                    }

                    /* segna il flusso come inutilizzato */
                    ptr->used = 0;
                }
            }
        }

        /* ritardo nel compiere il prossimo ciclo */
        usleep( MYPCAP_FLOW_CHECK_DELAY );
    }

    return NULL;
}

void mypcap_flow_init( int httpd )
{
    size_t i;

    /* inizializza la tabella */
    mypcap_hashtable_init( &mypcap_flow_hashtable , MYPCAP_FLOW_HASHTABLE_SLOTS );

    /* inizializza le code */
    memset( mypcap_rr_queues , 0 ,
            MYPCAP_FLOW_THREADS * MYPCAP_FLOW_RR_QUEUE_SIZE *
            sizeof( struct mypcap_flow_update_info ) );

    /* inizializza le cv */
    for ( i = 0 ; i < MYPCAP_FLOW_THREADS ; i++ )
    {
        assert( pthread_cond_init( &mypcap_rr_queues_cvs[ i ] , NULL ) == 0 );
    }

    /* crea i thread */
    for ( i = 0 ; i < MYPCAP_FLOW_THREADS ; i++ )
    {
        /* crea un thread inserter */
        if ( pthread_create( &mypcap_flow_inserters_id[ i ] , NULL ,
                             &mypcap_flow_inserter , ( void * )i ) )
        {
            perror( "pthread_create" );
            exit( errno );
        }
    }

    /* crea il thread che scorre i flussi */
    if ( pthread_create( &mypcap_flow_dumper_id, NULL , &mypcap_flow_dumper , ( void * )( size_t )httpd ) )
    {
        perror( "pthread_create" );
        exit( errno );
    }
}

void mypcap_flow_add( struct mypcap_flow_update_info *update_info )
{
    size_t thread_idx;
    struct mypcap_flow_update_info *elem_p;
    size_t *index_p;

    /* calcola l'hash e l'indice del thread */
    update_info->hash = mypcap_hashtable_hash( &mypcap_flow_hashtable , &update_info->key );
    thread_idx = update_info->hash % MYPCAP_FLOW_THREADS;

    /* prende l'elemento e l'indice di scrittura della coda */
    index_p = mypcap_rr_queues_indexes + thread_idx;
    elem_p = mypcap_rr_queues[ thread_idx ] + *index_p;

    /* inserisce le informazioni nella coda se l'elemento e' libero */
    if ( !elem_p->used )
    {
        /* copia le informazionni */
        memcpy( elem_p , update_info , sizeof( struct mypcap_flow_update_info ) );

        /* segna come utilizzato */
        elem_p->used = 1; /* per ultimo */

        /* va al successivo */
        *index_p = ( *index_p + 1 ) % MYPCAP_FLOW_RR_QUEUE_SIZE;

        /* segnala la disponibilita' */
        assert( pthread_cond_signal( &mypcap_rr_queues_cvs[ thread_idx ] ) == 0 );
    }
    /* drop */
    else fprintf( stderr , "queue full; dropped\n" );
}

void mypcap_flow_free()
{
    size_t i;

    /* libera le strutture dati dei thread inserter */
    for ( i = 0 ; i < MYPCAP_FLOW_THREADS ; i++ )
    {
        /* libera la cv e la dealloca */
        assert( pthread_cond_signal( &mypcap_rr_queues_cvs[ i ] ) == 0 );
        assert( pthread_cond_destroy( &mypcap_rr_queues_cvs[ i ] ) == 0 );
        assert( pthread_join( mypcap_flow_inserters_id[ i ] , NULL ) == 0 );
    }

    /* attende il thread dumper */
    assert( pthread_join( mypcap_flow_dumper_id , NULL ) == 0 );

    /* libera la hashtable */
    mypcap_hashtable_free( &mypcap_flow_hashtable );
}
