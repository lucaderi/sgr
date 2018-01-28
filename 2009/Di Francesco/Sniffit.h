
/*
 **********************************************************************
 ** Sniffit.h -- Header file for implementation of Sniffit           **
 **                                                                  **
 ** Created: 09/07/2009  SGR project                                 **
 **                                                                  **
 ** Sniffit is a tool that reads packets live or from a pcap file    **
 **                                                                  **
 ** By Giuseppe Di francesco  <difrance@cli.di.unipi.it>             **
 **                                                                  **
 **                                                                  **
 **********************************************************************
 */

#ifndef SNIFFIT_H
#define SNIFFIT_H
#define CAPACITY 1000            /* dimensione coda */

#include <stdbool.h>

//definisco struttura del messaggio
typedef struct msg {
   int protocol;               /* tipo di protocollo di trasporto   */
   char *s;                    /* indirizzo sorgente formattato     */
   char *d;                    /* indirizzo destinatario formattato */
   unsigned short source;      /* porta sorgente                    */
   unsigned short dest;        /* porta destinatario                */	
   in_addr_t ip_src;           /* indirizzo ip sorgente             */ 	
   in_addr_t ip_dst;           /* indirizzo ip destinatario         */
   int dir;                    /* direzione pacchetto               */	 
   int packet_bytes;           /* # bytes                           */
   time_t timestamp;           /* timestamp del pacchetto           */ 	
}msg;

//definisco struttura per i flussi
typedef struct flow{
   char *s;                    /* indirizzo ip sorgente                                 */
   char *d;                    /* indirizzo ip destinatario                             */  
   int protocol;               /* protocollo                                            */
   int pkt_b_s;                /* numero di byte  dal sorgente al destinatario          */
   int pkt_c_s;                /* numero di pacchetti dal sorgente al destinatario      */
   int pkt_b_d;                /* numero di byte  dal destinatario al sorgente          */
   int pkt_c_d;                /* numero di pacchetti dal destinatario al sorgente      */
   int dir;                    /* direzione del pacchetto se è 0 è dal sorgente al dest */
   unsigned short ps;          /* porta sorgente                                        */
   unsigned short pd;          /* porta destinatario                                    */
   time_t timestamp_first;     /* timestamp al momento della cattura                    */
   time_t timestamp_last;      /* timestamp al momento dell'aggiornamento               */
}FLOW;

//definisco la mia coda
typedef struct coda {
   char nome[10];
   msg buffer[CAPACITY];
   int capacity;
   int head;
   int tail;
   pthread_mutex_t lock;       
   pthread_cond_t notempty;  
}coda;

// elemento della lista della tabella hash
struct nlist {
    struct nlist *next;
    msg *data;
    FLOW *flusso;
};

coda *creaCoda(int capacity);
bool isEmpty(coda * c);
bool isFull(coda * c);
bool enqueue(msg *mess, coda *c);
msg* dequeue(coda *c);
struct nlist *lookup(int key, msg *mess);
int install(int key,msg * mess);
int hashtbl_remove();

/*
 **********************************************************************
 ** End of Sniffit.h                                                 **
 ******************************* (cut) ********************************
 */
#endif 
