#include "hash.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

//PWJ hash function
u_int hash(u_long key, u_int buckets) {
    key = ((key >> 32) ^ key) * 0x45d9f3b;
    key = ((key >> 32) ^ key) * 0x45d9f3b;
    key = (key >> 32) ^ key;
    return key % buckets;
}

void ll_sum_data(host_data_t *a, host_data_t *b) {
    a->udp_bytes += b->udp_bytes;
    a->tcp_bytes += b->tcp_bytes;
    a->icmp_bytes += b->icmp_bytes;

}

void hash_init(ht_t *ht, ssize_t bucketsnum) {
    ht->table = (ll_elem_t **) calloc(bucketsnum, sizeof(ll_elem_t *));
    ht->buckets = bucketsnum;
}

void hash_free(ht_t *ht) {
    free(ht->table);
    free(ht);
}

void hash_insert(ht_t *ht, host_data_t *data) {
    //the key used is the ip addresses pair concatenated as a long int
    u_long key = (data->ipaddr_tx << 32) | data->ipaddr_rx;
    data->key = key;
    ssize_t position = hash(key, ht->buckets);
    ht->table[position] = ll_insert(ht->table[position], data);
}

ll_elem_t *ll_insert(ll_elem_t *head, host_data_t *tbadd) {

    ll_elem_t *curr = head;
    while (curr != NULL) {
        if (curr->data.key == tbadd->key) {
            ll_sum_data(&curr->data, tbadd);
            curr->pktcount++;
            return head;
        }
        curr = curr->next;
    }

    ll_elem_t *new = (ll_elem_t *) calloc(1, sizeof(ll_elem_t));
    new->data.key = tbadd->key;
    new->data.ipaddr_tx = tbadd->ipaddr_tx;
    new->data.ipaddr_rx = tbadd->ipaddr_rx;
    new->data.udp_bytes = tbadd->udp_bytes;
    new->data.tcp_bytes = tbadd->tcp_bytes;
    new->data.icmp_bytes = tbadd->icmp_bytes;
    new->pktcount = 1;
    new->prev = NULL;
    new->next = head;
    if (head) head->prev = new;
    return new;
}

void hash_to_json(FILE *fp, ht_t *ht) {
    char tx_buf[IP_STR_MAX];
    char rx_buf[IP_STR_MAX];

    fprintf(fp, "const jsonData = {\"dataset\":[\n\n");

    for (u_int i = 0; i < ht->buckets; i++) {
        ll_elem_t *curr = ht->table[i];
        while (curr != NULL) {
            struct in_addr tx_addr;
            struct in_addr rx_addr;
            tx_addr.s_addr = curr->data.ipaddr_tx;
            rx_addr.s_addr = curr->data.ipaddr_rx;
            strcpy(tx_buf, inet_ntoa(tx_addr));
            strcpy(rx_buf, inet_ntoa(rx_addr));

            fprintf(fp, JSON_FORMAT, tx_buf, rx_buf, curr->pktcount, curr->data.udp_bytes,
                    curr->data.tcp_bytes, curr->data.icmp_bytes);
            curr = curr->next;
        }
    }
    fprintf(fp, "]}");
}
