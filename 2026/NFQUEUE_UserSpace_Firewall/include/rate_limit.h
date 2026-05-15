#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <time.h>
#include "packet.h"

// COSTANTI LEAKY BUCKET

// Numero massimo di IP sorgenti tracciabili.
#define MAX_BUCKETS 1024

// Soglia massima del bucket.
// Se un IP supera questo valore, viene bloccato.
#define RATE_LIMIT_MAX_TOKENS 10

// Velocità con cui il bucket si svuota.
// Qui: 1 token rimosso al secondo.
#define RATE_LIMIT_LEAK_RATE 1

#define RATE_LIMIT_OK     0
#define RATE_LIMIT_DROP   1
#define RATE_LIMIT_ERROR -1

// STRUTTURA BUCKET

// Ogni IP sorgente ha un bucket.
// Più pacchetti manda, più tokens accumula.
// Col tempo i tokens diminuiscono.
typedef struct {
    char ip[16];             // IP sorgente associato al bucket
    int tokens;              // livello attuale del bucket
    time_t last_update;      // ultimo momento in cui il bucket è stato aggiornato
    int used;                // 1 se questo slot è occupato
} bucket_t;

// API

// Inizializza la tabella dei bucket.
int rate_limit_init(void);

// Controlla se un pacchetto supera il rate limit.
// Ritorna 1 se va bloccato, 0 se può continuare.
int rate_limit_check(packet_t *pkt);
const char *rate_limit_last_error(void);

#endif
