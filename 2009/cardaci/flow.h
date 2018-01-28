#ifndef __MYPCAP_FLOW_H__
#define __MYPCAP_FLOW_H__

#include <arpa/inet.h>

/* massino tempo di attivita' di un flusso prima di essere scartato */
#define MYPCAP_FLOW_MAX_ACTIVITY_TIME 60

/* massimo tempo di inattivita' di un flusso prima di essere
   scartato */
#define MYPCAP_FLOW_MAX_INACTIVITY_TIME 10

/* tempo che deve trascorrere dopo ogni scansione dei flussi per
   trovare quelli da scartare (microsecondi) */
#define MYPCAP_FLOW_CHECK_DELAY 100000

/* dimensione delle code circolari */
#define MYPCAP_FLOW_RR_QUEUE_SIZE 100

/* slots della tabella hash */
#define MYPCAP_FLOW_HASHTABLE_SLOTS 10000

/* threads che aggiornano la tabella hash */
#define MYPCAP_FLOW_THREADS 10

/* ip + porta */
struct mypcap_host
{
    struct in_addr ip;
    uint16_t port;
};

/* definisce un flusso; chiave: ip_s + porta_s + ip_d + porta_d */
struct mypcap_flow_key
{
    struct mypcap_host src , dst;
    /* [...] */
};

/* dati da mantenere per ogni flusso */
struct mypcap_flow_data
{
    uint32_t pkts;
    uint32_t bytes;
    time_t fst;     /* timestamp del primo pacchetto */
    time_t lst;     /* timestamp dell'ultimo pacchetto */
    /* [...] */
};

/* informazioni richieste per l'aggiornamento di un flusso all'arrivo
   di un pacchetto */
struct mypcap_flow_update_info
{
    struct mypcap_flow_key key;    /* identificatore */
    uint32_t hash;                 /* hash */
    unsigned int used:1;           /* flag di uso per le code circolari */
    uint32_t bytes;                /* dimensione del pacchetto */
    time_t lst;                    /* timestamp dell'arrivo del pacchetto */
    /* [...] */
};

/* inizializza la gestione dei flussi */
void mypcap_flow_init( int httpd );

/* aggiunge un pacchetto alle code */
void mypcap_flow_add( struct mypcap_flow_update_info *update_info );

/* finalizza la gestione dei flussi */
void mypcap_flow_free();

#endif
