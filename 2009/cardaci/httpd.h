#ifndef __MYPCAP_HTTPD_H__
#define __MYPCAP_HTTPD_H__

#include "flow.h"

/* numero di flussi da mostrare nella pagina http */
#define MYPCAP_HTTPD_MAX_FLOWS 10

/* buffer per la costruzione della pagina */
#define MYPCAP_HTTPD_PAGE_BUFFER_SIZE 100000

/* file temporaneo per la creazione del grafico */
#define MYPCAP_HTTPD_TEMP_FILE "/tmp/mypcap" /* TODO: Nome dinamico. */

/* informazioni su un flusso da mostrare nella pagina */
struct mypcap_httpd_flow
{
    struct mypcap_flow_key key;
    struct mypcap_flow_data data;
};

/* avvia il server http */
void mypcap_httpd_init( int port , int rrd , int flow );

/* aggiunge un flusso alla coda circolare */
void mypcap_httpd_push_flow( struct mypcap_flow_key *key ,
                             struct mypcap_flow_data *data );

/* libera le risorse del server http */
void mypcap_httpd_free();

#endif
