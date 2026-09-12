#ifndef FLOW_H
#define FLOW_H

#include <sys/types.h>

typedef struct flow_data {
    u_int32_t start_time;
    u_int32_t end_time;
    
    u_int8_t  srcaddr[16];
    u_int8_t  dstaddr[16];
    
    u_int32_t dPkts;
    u_int32_t dOctets;
    u_int16_t srcport;
    u_int16_t dstport;
    u_int8_t  prot;
} __attribute__((packed)) flow_data;

#endif