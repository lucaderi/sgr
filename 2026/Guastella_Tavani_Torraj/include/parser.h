#ifndef PARSER_H
#define PARSER_H

#include "packet.h"  // per packet_t

// Parsa pacchetto raw → packet_t
// return: 1 = OK, 0 = errore
int parse_packet(unsigned char *data, int len, packet_t *pkt);

#endif