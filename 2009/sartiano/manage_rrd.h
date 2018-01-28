#ifndef __MANAGE_RRD_H
#define __MANAGE_RRD_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* manage_rrd_name_image;

/* Assegna il nome dell'immagine del grafico creato */
void assign_name_image(char*);

/* Crea il rrd con il nome passato come argomento*/
int create_rrd(char* );

/* Crea il grafico ottenuto leggendo i valori sul rrd
 * passando come parametro il nome del file rrd*/
int create_graph(char* );

/* Effettua l'update al rrd passato come primo argomento,
 * con i valori: pacchetti totali, pacchetti tcp, pacchetti udp,
 * pacchetti icmp, passati come argomenti*/
int update_rrd(char*, int, int, int, int);


#endif
