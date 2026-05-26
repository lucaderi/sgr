#ifndef HYPERLOGLOG_H
#define HYPERLOGLOG_H

#include <stdint.h>

#define HLL_OK      0
#define HLL_ERROR  -1

// CONFIGURAZIONE HYPERLOGLOG

// HLL_P indica quanti bit usiamo per scegliere il registro.
// Con P=10 abbiamo 2^10 = 1024 registri.
#define HLL_P 10
#define HLL_M (1 << HLL_P)

// Inizializza i registri HyperLogLog.
int  hll_init(void);

// Aggiunge un IP sorgente alla stima.
int  hll_add_ip(const char *src_ip);

// Restituisce la stima del numero di IP sorgenti unici.
int hll_get_cardinality(void);

const char *hll_last_error(void);

#endif
