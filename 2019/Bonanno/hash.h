#ifndef GDR19_HASH_H
#define GDR19_HASH_H

#define JSON_FORMAT "{\"tx_addr\":\"%s\",\n\"rx_addr\":\"%s\",\n\"pktcount\":%u,\n\"udp_bytes\":%u,\n\"tcp_bytes\":%u,\n\"icmp_bytes\":%u},\n\n"
#define IP_STR_MAX 16

#include <sys/param.h>
#include <stdio.h>

typedef struct host_data_t {
    u_int key;
    u_int ipaddr_tx;
    u_int ipaddr_rx;
    u_int tcp_bytes;
    u_int udp_bytes;
    u_int icmp_bytes;
} host_data_t;

typedef struct ll_elem_t {
    struct ll_elem_t *next;
    struct ll_elem_t *prev;
    host_data_t data;
    u_int pktcount;
} ll_elem_t;

typedef struct ht_t {
    u_int buckets;
    struct ll_elem_t **table;
} ht_t;

void hash_init(ht_t *ht, ssize_t bucketsnum);

void hash_insert(ht_t *ht, host_data_t *data);

ll_elem_t *ll_insert(ll_elem_t *head, host_data_t *data);

void hash_free(ht_t *ht);

void hash_to_json(FILE *fp, ht_t *ht);

#endif //GDR19_HASH_H
