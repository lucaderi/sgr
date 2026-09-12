#ifndef NF9_PARSER_H
#define NF9_PARSER_H

#include <sys/types.h>
#include "flow.h"
#include "ring_buffer.h"

void parse_nf9_packet(const u_int8_t *buffer, int length, rbuffer *rb);

#endif