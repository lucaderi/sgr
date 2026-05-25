#ifndef NFQUEUE_CORE_H
#define NFQUEUE_CORE_H

#include <stdint.h>

// Packet mark usati insieme a iptables CONNMARK.
#define FW_MARK_NONE 0x0
#define FW_MARK_PASS 0x1
#define FW_MARK_DROP 0x2

// CALLBACK DEFINITA DAL LIVELLO SUPERIORE
// Ritorna:
// 1 = ACCEPT
// 0 = DROP

typedef int (*packet_handler_cb)(
    unsigned char *data,
    int len
);

// Inizializza NFQUEUE e registra callback
int nfqueue_init(packet_handler_cb cb);

// Loop principale (blocking)
void nfqueue_run();

// Cleanup risorse
void nfqueue_cleanup();

#endif
