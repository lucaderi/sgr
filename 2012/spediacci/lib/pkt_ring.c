#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>
#include <string.h>

#include "pkt_ring.h"
#include "includes.h"

#define BUFFER_PAGE_SIZE 10

int pkt_ring_init(pkt_ring *ring) {
  u_int32_t page_s = sysconf(_SC_PAGE_SIZE);
  int shm_id;
  ring->len = page_s * BUFFER_PAGE_SIZE;
  ring->buffer = mmap (NULL, ring->len << 1, PROT_READ | PROT_WRITE,
	MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ring->buffer == MAP_FAILED)
    return -1;
  shm_id = shmget(IPC_PRIVATE, ring->len, IPC_CREAT);
  if (shm_id == -1 ||
      shmat(shm_id, ring->buffer, SHM_REMAP) == (void *) -1) {
    munmap(ring->buffer, ring->len << 1);
    return -1;
  }
  if (shmat(shm_id, ring->buffer + ring->len, SHM_REMAP) == (void *) -1) {
    shmdt(ring->buffer);
    return -1;
  }
  ring->start = ring->end = ring->buffer;
  ring->buffer_end = ring->buffer + ring->len;
  ring->read_lap = ring->write_lap = 0;
  return 0;
}

int pkt_ring_write(pkt_ring *ring, void *data, size_t len, struct sockaddr_in *addr) {
  u_int32_t req_size = len + sizeof(struct sockaddr_in) + sizeof(size_t);
  if ((ring->start != ring->end || ring->read_lap == ring->write_lap) &&
      (u_int32_t) (ring->buffer_end - ring->end + ring->start - ring->buffer) >= req_size) {
    void *p = ring->end;
    int empty = ring->start == ring->end && ring->read_lap == ring->write_lap;
    memcpy(p, addr, sizeof(struct sockaddr_in));
    p += sizeof(struct sockaddr_in);
    *((size_t *) p) = len;
    p += sizeof(size_t);
    memcpy(p, data, len);
    p += len;
    if (p > ring->buffer_end) {
      p -= ring->len;
      ring->write_lap++;
    }
    ring->end = p;
    return empty ? 1 : 0;
  }
  return -1;
}

ssize_t pkt_ring_read(pkt_ring *ring, void *data, size_t len, struct sockaddr_in *addr) {
  if (ring->start != ring->end || ring->read_lap < ring->write_lap) {
    void *p = ring->start;
    size_t pkt_len, copied;
    memcpy(addr, p, sizeof(struct sockaddr_in));
    p += sizeof(struct sockaddr_in);
    pkt_len = *((size_t *) p);
    p += sizeof(size_t);
    copied = min(pkt_len, len);
    memcpy(data, p, copied);
    p += copied;
    if (p > ring->buffer_end) {
      p -= ring->len;
      ring->read_lap++;
    }
    ring->start = p;
    return copied;
  }
  return -1;
}

void pkt_ring_free(pkt_ring *ring) {
  munmap(ring->buffer, ring->len << 1);
  shmdt(ring->buffer);
}
