#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include "hyperloglog.h"
#include <arpa/inet.h>


static const char *last_error = "no error";

const char *hll_last_error(void) {
    return last_error;
}

// STORAGE HYPERLOGLOG

// WORKFLOW:
// Questi registri vivono per tutta l'esecuzione.
// Ogni pacchetto aggiorna la stima degli IP sorgenti unici.
static unsigned char registers[HLL_M];

#define HLL_HASH_BITS 32
#define HLL_REMAINING_BITS (HLL_HASH_BITS - HLL_P)

// HASH IPV4

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;

    return x;
}


// WORKFLOW:
// Questa funzione viene chiamata quando hll_add_ip() riceve l'IP sorgente del pacchetto dal Decision Engine.
static int hash_ipv4(const char *ip, uint32_t *out_hash) {
    
    struct in_addr addr;
    uint32_t ip_value;

    if (ip == NULL || out_hash == NULL) {
        last_error = "NULL argument in hash_ipv4";
        return HLL_ERROR;
    }

    // Converte la stringa "192.168.1.10" in numero binario IPv4.
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        last_error = "invalid IPv4 address";
        return HLL_ERROR;
    }

    // ntohl porta il valore in ordine host. (da Big-Endian a Little-Endian)
    ip_value = ntohl(addr.s_addr);

    // XOR con una costante per evitare che 0.0.0.0 produca hash 0.
    *out_hash = mix32(ip_value ^ 0x9e3779b9u);

    return HLL_OK;
}


// COUNT ZEROS

#if !defined(__GNUC__)
// Conta quanti zeri iniziali ci sono nei bit rimanenti dell'hash. Più zeri iniziali troviamo, più è probabile che il numero di elementi distinti osservati sia alto, e quindi anche il rank.
static int hll_rank_slow(uint32_t value) {
    //si parte dal rank più basso
    int rank  = 1;

    //il rank massimo è quando tutti i bit rimanenti sono 0
    int max_rank = HLL_REMAINING_BITS + 1; 

    if (value == 0) {
        return max_rank;
    }

    //0x80000000u è una maschera che ha il bit più significativo ad 1, e tutti gli altri a 0. 
    //in pratica si guarda solo il bit più a sinistra, finchè è 0 si aumenta il rank e si passa al bit successivo.
    //Quando l'AND è un 1, significa che sono finiti gli zeri successivi e abbiamo incontrato un 1. Quindi ci fermiamo e restituiamo il rank
    while ((value & 0x80000000u) == 0 && rank < max_rank) {
        rank++;
        value <<= 1;
    }

    return rank;
}
#endif

//GCC offre la possibilità di contare il numero di 0 successivi direttamente in hardware come visto a lezione--> Possibile implementazione più efficiente 

// __builtin_clz conta gli zeri iniziali usando istruzioni efficienti.
// ATTENZIONE: non va mai chiamata con value == 0.
static int hll_rank_fast(uint32_t value) {
    if (value == 0) {
        return HLL_REMAINING_BITS + 1;
    }

#if defined(__GNUC__)
    int rank = __builtin_clz(value) + 1;

    //Limito il rank massimo
    if (rank > HLL_REMAINING_BITS + 1) {
        return HLL_REMAINING_BITS + 1;
    }

    return rank;
#else
    return hll_rank_slow(value);
#endif
}


// INIT

// WORKFLOW:
// Questa funzione va chiamata all'avvio del firewall,
// idealmente dentro decision_init().
int  hll_init(void) {
    
    for (int i = 0; i < HLL_M; i++) {
        registers[i] = 0;
    }

    last_error = "no error";
    return HLL_OK;
}

// AGGIUNGI IP

// WORKFLOW:
// Questa funzione viene chiamata all'inizio di decide().
// Il pacchetto non viene ancora accettato o bloccato: stiamo solo aggiornando le statistiche.
int  hll_add_ip(const char *src_ip) {
    
    uint32_t hash;
    uint32_t index;
    uint32_t remaining_bits;
    int rank;

    if (src_ip == NULL || src_ip[0] == '\0') {
        last_error = "invalid source IP in hll_add_ip";
        return HLL_ERROR;
    }

    if (hash_ipv4(src_ip, &hash) != HLL_OK) {
        return HLL_ERROR;
    }

    // I primi HLL_P bit scelgono quale registro aggiornare.
    index = hash >> (32 - HLL_P);

    // I bit rimanenti servono per calcolare il rank.
    remaining_bits = hash << HLL_P;

    // Versione lenta:
    // rank = hll_rank_slow(remaining_bits);

    // Versione ottimizzata con GCC:
    rank = hll_rank_fast(remaining_bits);

    // Ogni registro mantiene il massimo rank osservato.
    if (rank > registers[index]) {
        registers[index] = rank;
    }

    last_error = "no error";
    return HLL_OK;
}

// STIMA CARDINALITA'

// WORKFLOW:
// Questa funzione viene chiamata dal logging del Decision Engine, per esempio ogni 50 pacchetti.
// Non influisce direttamente su ACCEPT/DROP.
// Ci restituisce la cardinalità stimata
int hll_get_cardinality(void) {
    
    double alpha;
    double sum = 0.0;
    double estimate;
    int zero_registers = 0;


    alpha = 0.7213 / (1.0 + 1.079 / HLL_M); //costante di correzione (i valori derivano da studi matematici complessi fatti dall'inventore dell HLL). Serve a correggiere la sovrastima del numero degli elementi 

    //Media armonica dei valori dei registri. (Viene preferita alla media classica perchè dà meno peso ai valori estremi che influenzerebbero troppo la misura)
    for (int i = 0; i < HLL_M; i++) {
        sum += pow(2.0, -registers[i]); 
        
        if (registers[i] == 0) {
            zero_registers++;
        }
    }

    if (sum == 0.0) {
        last_error = "invalid HLL sum";
        return HLL_ERROR;
    }
    
    estimate = alpha * HLL_M * HLL_M / sum;  //formula di stima

    // Correzione utile per piccoli numeri di IP.
    // Senza questa correzione, HyperLogLog tende a sovrastimare molto quando sono stati visti pochi IP.
    if (estimate <= 2.5 * HLL_M && zero_registers > 0) {
        estimate = HLL_M * log((double)HLL_M / zero_registers);
    }

    if (!isfinite(estimate)) {
        last_error = "invalid HLL estimate";
        return HLL_ERROR;
    }

    last_error = "no error";
    return (int)(estimate + 0.5);
}
