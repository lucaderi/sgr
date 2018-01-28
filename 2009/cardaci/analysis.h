#ifndef __MYPCAP_ANALYSIS_H__
#define __MYPCAP_ANALYSIS_H__

#include <pcap.h>

/* parametri da passare all'handler */
struct mypcap_pkt_handler_params
{
    int dl_hdr_len;           /* lunghezza dell'header datalink  */
    int simple_info_dump;     /* flag per la stampa dei pacchetti */
    int net_flow_dump;        /* flag per il calcolo dei flussi */
};

/* lunghezze dell'header datalink */
int mypcap_datalink_header_lengths( int datalynk_type , int *offset );

/* handler eseguito ogni volta che arriva un pacchetto */
void mypcap_pkt_handler( u_char *user ,
                         const struct pcap_pkthdr *pkt_header ,
                         const u_char *pkt );

#endif
