#pragma once

#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <semaphore.h>
#include <pfring.h>

#include "hashtable.h"
#include "pkt_ring.h"

#define DNASTACK_DEBUG

#define MTU 1500
#define ARP_CACHE_LEN 5

struct __PfSocket;
typedef struct __PfSocket PfSocket;
struct __DnaSocket;
typedef struct __DnaSocket DnaSocket;

#define MAX_PORT 65535
extern DnaSocket *skts[MAX_PORT + 1];

typedef struct {
  struct in_addr addr;
  struct ether_addr mac;
  time_t timeout;
  time_t last_used;
} arp_entry;

struct __PfSocket {
  pfring *skt;
  struct ether_addr mac;
  struct in_addr addr;

  pthread_t reader;

  /* ARP CACHE */
  void *arp_cache;
  u_int arp_cache_count;
  pthread_mutex_t arp_cache_mutex;
  pthread_cond_t arp_cache_cond;
  int n_arp_readers;

  Hashtable_t *arp_table;

  int shutdown_arp;

  pthread_spinlock_t write_lock;

  /* skt stats  */
  u_int64_t pkt_recv, pkt_drop, pkt_send;
};

typedef struct {
  u_int8_t proto_id;
  u_int16_t (*make_hdr)(const struct ether_header *eth,
			const struct ip *ip,
			const char *msg,
			size_t msg_len,
			const struct sockaddr_in *addr,
			const DnaSocket *skt);
} proto_t;

struct __DnaSocket {
  PfSocket *skt;
  u_int16_t port;
  u_int16_t id;
  proto_t proto;

  /* enforce reliability in case of misuse of the library by
     checking these values before freeing socket resources */
  int is_sending, is_reading;

  int shutdown;

  /* ARP CACHE STUFF */
  arp_entry arp_cache[ARP_CACHE_LEN];
  arp_entry *ipop_arp_cache;
  arp_entry *iget_arp_cache;
  
  /* ZERO COPY */
  int z_stat;
  void *z_buffer;
  ssize_t z_len;
  struct sockaddr_in *z_addr;

  /* ring buffer for storing pkts */
  pkt_ring ring;
  sem_t sem;

  /* skt stats */
  u_int64_t pkt_recv, pkt_zero, pkt_drop;
};

extern DnaSocket *dnasocket_open();
extern int dnasocket_close(DnaSocket *skt);
extern void dnasocket_free(DnaSocket *skt);
extern int dnastack_init();
extern int dnastack_kill();
extern ssize_t dnasocket_recvfrom(void *buf, size_t len, int flags, struct sockaddr_in *src_addr, DnaSocket *skt);
extern ssize_t dnasocket_sendto(const char *msg, size_t msg_len, int flags, const struct sockaddr_in *addr, DnaSocket *skt);
extern int dnasocket_bind(const struct sockaddr_in *addr, DnaSocket *skt);
extern void search_closed_sockets();
extern void shutdown_all_sockets();
extern void dnastack_stats();

extern ssize_t read_pkt(void *buffer, size_t buffer_len, struct sockaddr_in *addr, DnaSocket *skt);
extern int parse_pkt(void *data, size_t pkt_len, int isdna, void *skt);
