#ifndef __MYPCAP_CAPTURE_H__
#define __MYPCAP_CAPTURE_H__

#include <pcap.h>
#include "analysis.h"

/* funzione che restituisce le lunghezze degli header datalink
   supportati; deve restituire 0 in caso di successo; non-0 se il
   protocollo non e' supportato */
typedef int ( * mypcap_dl_hdr_len_handler )( int , int* );

/* inizia la cattura; restituisce 0 in caso di successo; in caso
   contrario i messaggi di errore sono conservati nella variabile
   mypcap_err_buf */
int mypcap_start_capture( const char *dev_name ,                      /* device di cattura */
                          int snaplen ,                               /* porzione di pacchetto da catturare */
                          int pkt_cnt ,                               /* massimo numero di pacchetti da catturare */
                          int promisc ,                               /* modalita' promiscua  */
                          const char *bpf_filter ,                    /* filtro bpf */
                          pcap_direction_t pcap_dir ,                 /* direzione dei pacchetti catturati */
                          pcap_handler pkt_handler ,                  /* handler */
                          mypcap_dl_hdr_len_handler dl_hdr_len_fun ,  /* callback per la lunghezza dell'header DL */
                          struct mypcap_pkt_handler_params *params ); /* parametri */

/* interrompe il loop della cattura dei pacchetti */
void mypcap_break_capture();

/* dealloca le strutture dati */
void mypcap_capture_cleanup();

/* cambia l'utente se il programma e' stato eseguito tramite sudo */
int mypcap_change_user();

#endif
