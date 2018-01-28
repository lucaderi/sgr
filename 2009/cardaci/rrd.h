#ifndef __MYPCAP_RRD_H__
#define __MYPCAP_RRD_H__

#include <stddef.h>

/* intervallo di aggiornamento dei dati rrd (secondi) */
#define MYPCAP_RRD_STEP 5

/* numero di misurazioni originali da mantenere */
#define MYPCAP_RRD_FULL_AVG_STEPS 120

/* quanti valori utilizzare per calcolare il massimo */
#define MYPCAP_RRD_MAX_STEPS 10 /* TODO: Decisamente inutile. */

/* quanti valori del massimo tenere */
#define MYPCAP_RRD_MAX_SAMPLES 100

/* relazione tra step e heartbeat */
#define MYPCAP_RRD_HEARTBEAT_RATIO 1.3

/* informazioni da passare al database rrd */
struct mypcap_rrd_info
{
    size_t tcp_packets;
    size_t udp_packets;

    /* [...] altri dati per rrd */
};

/* crea il database rrd */
int mypcap_rrd_create();

/* aggiorna il database rrd */
int mypcap_rrd_update();

/* genera un grafico dai dati rrd */
int mypcap_rrd_graph( char *path );

#endif
