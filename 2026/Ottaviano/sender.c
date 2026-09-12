#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "structure.h"

#define ETHERNET 14
#define LEN_IP_HEADER 20
#define LEN_UDP_HEADER 8
#define LEN_PAYLOAD 36
#define MAX_LINE 32
#define MAX_ADDRESSES 32

char* interface = NULL;
FILE* fp = NULL;
uint16_t packet_id = -1;

void print_help(){
    printf("Usage:\n");
    printf("-i [interface]\n");
    printf("-f [file]\n");
    printf("-d [id packet (number)]\n");
}

void extract_params(char** argv, int argc){
    
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-i") == 0 && i + 1 < argc){
            interface = malloc(64);
            if(!interface){
                perror("malloc");
                exit(1);
            }
            strcpy(interface, argv[i+1]);
        } else if(strcmp(argv[i], "-f") == 0 && i + 1 < argc){
            fp = fopen(argv[i+1], "r");
            if(fp == NULL){
                perror("opening file");
                exit(1);
            }
        } else if(strcmp(argv[i], "-d") == 0 && i + 1 < argc){
            packet_id = (uint16_t)atoi(argv[i+1]);
        }
    }

    if(interface == NULL || fp == NULL || packet_id == -1){
        print_help();
        exit(1);
    }
}

int main(int argc, char** argv){

    /*
        estraggo i parametri nella riga di comando 
    */

    extract_params(argv, argc);

    char line[MAX_LINE];
    uint32_t addresses[MAX_ADDRESSES];
    int count = 0;

    /*
        inserisco gli indirizzi ip nell'array
    */

    while(fgets(line, sizeof(line), fp) != NULL){
        
        line[strcspn(line, "\n")] = '\0';

        if (count >= MAX_ADDRESSES) {
            fprintf(stderr, "array pieno\n");
            break;
        }

        uint32_t ip;

        if (inet_pton(AF_INET, line, &ip) == 1) {
            addresses[count++] = ip;
        } else {
            fprintf(stderr, "ip non valido: %s\n", line);
        }
    }

  
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, 65535, 1, 500, errbuf);

    if(!handle){
        fprintf(stderr, "pcap error: %s\n", errbuf);
        return -1;
    }

    unsigned char packet[sizeof(struct eth_header)+
    sizeof(struct ip_header_)+
    sizeof(struct udp_header_) +
    sizeof(struct payload)]; 
    memset(packet, 0, sizeof(packet));

    // ethernet
    struct eth_header *eth = (struct eth_header *)packet;
    uint8_t src_mac[6] = {0x00,0x0c,0x29,0x3e,0x5c,0x7d};
    uint8_t dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    memcpy(eth->src_mac, src_mac, 6);
    memcpy(eth->dst_mac, dst_mac, 6);
    eth->ethertype = htons(0x0800); // IPv4

    // ip
    struct ip_header_ *ip = (struct ip_header_ *)(packet + sizeof(struct eth_header));
    ip->vl = (4 << 4) | 5; // Version 4 + IHL 5
    ip->type_service = 0;
    ip->total_length = htons(sizeof(struct ip_header_) + sizeof(struct udp_header_));    
    ip->identification = packet_id;
    ip->fo = 0;
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->src_ip = htonl(0xc0a80164); // 192.168.1.100
    ip->dst_ip = htonl(0xc0a801ff); // 192.168.1.255
    ip->checksum = 0;
   
    // udp
    struct udp_header_ *udp = (struct udp_header_ *)(packet + sizeof(struct eth_header) + sizeof(struct ip_header_));
    udp->src_port = htons(1234);
    udp->dst_port = htons(4321);
    udp->length = htons(sizeof(struct udp_header_));
    udp->checksum = 0; // opzionale

    struct payload* p = (struct payload*)(packet + sizeof(struct eth_header)+
    sizeof(struct ip_header_) + sizeof(struct udp_header_));
    p->hop = 0;
    strcpy(p->message, "hello world!");

    int option;
    printf("range {0-%d}\n",count-1);
   
    while(1){

        scanf("%d", &option);
        if(option < 0 || option >= count) {
            printf("numero inserito fuori dal range!\n\n");
            continue;
        }
        ip->src_ip = addresses[option];

        if(pcap_sendpacket(handle, packet, SIZE_PACKET) != 0){
            fprintf(stderr, "send error: %s\n", pcap_geterr(handle));
            return -1;
        } else printf("pacchetto inviato!\n");
    }

    printf("pacchetto inviato!\n");

    free(interface);
    return 0;
}
