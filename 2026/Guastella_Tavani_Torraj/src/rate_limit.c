#include <string.h>
#include <time.h>
#include "rate_limit.h"

// STORAGE BUCKET

// WORKFLOW:
// Questa tabella vive per tutta l'esecuzione del firewall.
// Serve a ricordare il traffico recente di ogni IP sorgente.
static bucket_t buckets[MAX_BUCKETS];


//Mi segno l'ultimo errore in una stringa, così da sapere la causa di un eventuale errore
static const char *last_error = "no error";

const char *rate_limit_last_error(void) {
    return last_error;
}

// HASH IP

// Trasforma una stringa IP in un numero.
// Serve per scegliere rapidamente una posizione nella tabella.
// Hash: djb2, creata da Dan Bernstein
static unsigned int hash_ip(const char *ip) {
    //5381 è un numero primo con ottime proprietà statistiche per ridurre le collisioni iniziali
    unsigned int hash = 5381;

    //facnedo <<5 è come fare *33, e questo fa in modo di spalmare bene le stringhe, in modo tale che stringhe simili finiscano in punti distanti dalla tabella
    while (*ip != '\0') {
        hash = ((hash << 5) + hash) + (unsigned char)(*ip);
        ip++;
    }

    return hash;
}

// INIT

// WORKFLOW:
// Questa funzione va chiamata all'avvio del programma,
// idealmente dentro decision_init().
int rate_limit_init(void) {

    time_t now = time(NULL);

    if (now == (time_t)-1) {
        last_error = "time() failed during rate_limit_init";
        return RATE_LIMIT_ERROR;
    }

    for (int i = 0; i < MAX_BUCKETS; i++) {
        buckets[i].ip[0] = '\0';
        buckets[i].tokens = 0;
        buckets[i].last_update = now;
        buckets[i].used = 0;
    }

    last_error = "no error";
    return RATE_LIMIT_OK;
}

// CERCA O CREA BUCKET

// WORKFLOW:
// Quando arriva un pacchetto, dobbiamo trovare il bucket
// associato al suo IP sorgente.
// Se non esiste ancora, lo creiamo.
static bucket_t *find_or_create_bucket(const char *ip) {

    unsigned int index = hash_ip(ip) % MAX_BUCKETS;
    unsigned int start = index;

    // Se la posizione è occupata da un altro IP, proviamo la posizione successiva.
    while (buckets[index].used) {

        if (strcmp(buckets[index].ip, ip) == 0) {
            return &buckets[index];
        }

        index = (index + 1) % MAX_BUCKETS;

        // Se torniamo al punto di partenza, la tabella è piena.
        if (index == start) {
            return NULL;
        }
    }

    // Creazione nuovo bucket.
    buckets[index].used = 1;
    strncpy(buckets[index].ip, ip, 15);
    buckets[index].ip[15] = '\0';
    buckets[index].tokens = 0;
    buckets[index].last_update = time(NULL);

    return &buckets[index];
}

// CORE RATE LIMITING

// WORKFLOW:
// Questa funzione viene chiamata dal Decision Engine
// dopo il controllo delle regole statiche.
//
// Logica:
// - ogni pacchetto aumenta il livello del bucket
// - il tempo fa diminuire il livello del bucket
// - se il livello supera la soglia, il pacchetto viene droppato
int rate_limit_check(packet_t *pkt) {

    bucket_t *bucket;
    time_t now;
    int elapsed;
    int leaked_tokens;


    if (pkt == NULL) {
        last_error = "NULL packet in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    if (pkt->src_ip[0] == '\0') {
        last_error = "empty source IP in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    // Trova il bucket relativo all'IP sorgente del pacchetto.
    bucket = find_or_create_bucket(pkt->src_ip);

    if (bucket == NULL) {
        // Se non possiamo tracciare altri IP, scelta conservativa: blocchiamo il pacchetto.
        last_error = "bucket table full";
        return RATE_LIMIT_ERROR;
    }

    now = time(NULL);

    if (now == (time_t)-1) {
        last_error = "time() failed in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    elapsed = (int)(now - bucket->last_update);
    
    if (elapsed < 0) {
        elapsed = 0;
    }

    // Se è passato tempo dall'ultimo pacchetto, il bucket si svuota.
    if (elapsed > 0) {
        
        leaked_tokens = elapsed * RATE_LIMIT_LEAK_RATE;

        bucket->tokens -= leaked_tokens;

        if (bucket->tokens < 0) {
            bucket->tokens = 0;
        }

        bucket->last_update = now;
    }

    // Il pacchetto corrente aumenta il livello del bucket.
    bucket->tokens++;

    // Se il bucket supera la soglia, l'IP sta inviando troppo traffico.
    if (bucket->tokens > RATE_LIMIT_MAX_TOKENS) {
        last_error = "rate limit exceeded";
        return RATE_LIMIT_DROP;
    }

    last_error = "no error";
    return RATE_LIMIT_OK;
}
