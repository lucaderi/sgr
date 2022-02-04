#pragma once

#include <netinet/in.h>

typedef struct __pkt_ring {
  void *buffer, *buffer_end;
  void *start, *end;
  u_int32_t len;
  u_int read_lap, write_lap;
} pkt_ring;

extern int pkt_ring_init(pkt_ring *ring);
extern int pkt_ring_write(pkt_ring *ring, void *data, size_t len, struct sockaddr_in *addr);
extern ssize_t pkt_ring_read(pkt_ring *ring, void *data, size_t len, struct sockaddr_in *addr);
extern void pkt_ring_free(pkt_ring *ring);
