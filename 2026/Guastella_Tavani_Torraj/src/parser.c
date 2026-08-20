#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "parser.h"

//Packet Header
struct ip_header {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct tcp_header {
    unsigned short source;
    unsigned short dest;
};

struct udp_header {
    unsigned short source;
    unsigned short dest;
};

//Parser
int parse_packet(unsigned char *data, int len, packet_t *pkt){

    size_t packet_len;
    size_t ip_header_len;

    if (!data || !pkt) {
        return 0;
    }

    if (len <= 0) {
        return 0;
    }

    packet_len = (size_t)len;

    if (packet_len < sizeof(struct ip_header)) {
        return 0;
    }

    struct ip_header *ip = (struct ip_header *)data;

    // Solo IPv4
    if (ip->version != 4) {
        return 0;
    }

    // Validazione IHL
    if (ip->ihl < 5) {
        return 0;
    }

    ip_header_len = (size_t)ip->ihl * 4u;

    if (packet_len < ip_header_len) {
        return 0;
    }

    if (ntohs(ip->tot_len) < ip_header_len) {
        return 0;
    }

    // IP
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    if (inet_ntop(AF_INET, &src, pkt->src_ip, sizeof(pkt->src_ip)) == NULL) return 0;

    if (inet_ntop(AF_INET, &dst, pkt->dst_ip, sizeof(pkt->dst_ip)) == NULL) return 0;

    pkt->protocol = ip->protocol;

    // Default
    pkt->src_port = 0;
    pkt->dst_port = 0;

    // TCP
    if (ip->protocol == 6) {

        if (packet_len < ip_header_len + sizeof(struct tcp_header)) return 0;

        struct tcp_header *tcp = (struct tcp_header *)(data + ip_header_len);

        pkt->src_port = ntohs(tcp->source);
        pkt->dst_port = ntohs(tcp->dest);
    }

    // UDP
    else if (ip->protocol == 17) {
        
        if (packet_len < ip_header_len + sizeof(struct udp_header)) return 0;

        struct udp_header *udp = (struct udp_header *)(data + ip_header_len);

        pkt->src_port = ntohs(udp->source);
        pkt->dst_port = ntohs(udp->dest);
    }

    // ICMP
    else if (ip->protocol == 1) {
        pkt->src_port = 0;
        pkt->dst_port = 0;
    }

    return 1;
}
