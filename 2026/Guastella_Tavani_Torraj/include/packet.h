#ifndef PACKET_H
#define PACKET_H

// Rappresentazione standard di un pacchetto parsato
// Usata da TUTTI i moduli (parser, rules, rate limit, decision)
typedef struct {
    char src_ip[16];   // IPv4 string (es. "192.168.1.1")
    char dst_ip[16];
    int src_port;      // 0 se non applicabile (es. ICMP)
    int dst_port;
    int protocol;      // TCP=6, UDP=17, ICMP=1
} packet_t;

#endif