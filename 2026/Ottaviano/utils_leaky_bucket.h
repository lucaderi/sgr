#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <time.h>

#define DEFAULT_SNAPLEN 256
#define CAPACITY 2
#define TTL_IP_IN_BUCKET 5
#define TTL_IP_IN_BLACKLIST 7
#define SIZE 10

#include "structure.h"
#include <stdbool.h>

void print_ip32(uint32_t ip);

void print_bucket(struct Bucket** table);
void print_blacklist(struct Address_node** blacklist);
uint8_t hash(uint32_t ip);

long int calc_rem(struct Bucket* b);

void update_blacklist(uint8_t index, struct Address_node** blacklist);
bool ipInBlacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist);

void check_bucket(struct Bucket** table, struct Address_node** blacklist);

void free_buckets(struct Bucket** table);

void free_blacklist(struct Address_node** blacklist);
void process_packet(unsigned char* user,
    const struct pcap_pkthdr* h,
    const unsigned char* packet, pcap_t* in, pcap_t* out,
    struct Bucket** table, struct Address_node** blacklist,
    char* dev1, char* dev2);

void insert_ip_in_blacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist);
#endif
