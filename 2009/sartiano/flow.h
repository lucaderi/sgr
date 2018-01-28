#ifndef __FLOW_H
#define __FLOW_H

#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

typedef struct struct_flow_key {
	in_addr_t ip_src, ip_dst;
	u_int16_t port_src, port_dst;
} flow_key;

typedef struct struct_flow {
	flow_key *key;
	u_int length; //byte
	u_int pkts;  //pkt number
	struct timeval first;
	struct timeval last;
} flow;

/* Restituisce 0 se le chiavi sono uguali, altrimenti 1 */
int flow_cmp(flow*, flow*);

/* Crea una chiave passando come parametri: ip_src, ip_dst, port_src, port_dst */
flow_key* flow_key_create(in_addr_t, in_addr_t, u_int16_t, u_int16_t);

/* Crea un flusso passando come paramtri: la relativa chiave, la lunghezza, il numero di pacchetti,
 * il timestamp della prima volta che entrato e il timestamp dell'ultima volta che è stato aggiornato*/
flow* flow_create(flow_key*, u_int, u_int, struct timeval, struct timeval);

/* Restituisce una stringa costituita da latitudine, longitudine e ip del flusso passato come argomento */
char* flow_get_geo_info(flow*, GeoIP*);

/* Stampa a video le informazioni relative al flusso passato come parametro */
void flow_print_export(flow *f);

/* Restituisce una stringa contente le informazioni relative al flusso passato come argomento */
char* flow_create_string(flow *f);

#endif
