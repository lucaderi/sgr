#ifndef STRUCTURE_H
#define STRUCTURE_H

#define ETH_ALEN 6



struct eth_header {
    uint8_t dst_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ethertype;
} __attribute__((packed));

struct ip_header_ {
    uint8_t  vl;              
    uint8_t  type_service;    
    uint16_t total_length;
    uint16_t identification;
    uint16_t fo;              
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct udp_header_ {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct payload {
    uint32_t hop;
    char message[32];
} __attribute__((packed));

#define SIZE_PACKET (sizeof(struct eth_header) + sizeof(struct ip_header_) + sizeof(struct udp_header_) + sizeof(struct payload))

struct Bucket {
    uint32_t ip;
    unsigned int level;
    time_t timestamp;
    struct Bucket* next;
};

struct Address_node {
    uint32_t ip;
    time_t timestamp;
    struct Address_node* next;
};

#endif
