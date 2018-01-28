#include <stdio.h>
#include <ifaddrs.h>
#include <time.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>

#include "dnastack.h"
#include "arp.h"
#include "read.h"
#include "includes.h"
#include "send.h"
#include "udp.h"
#include "pkt_ring.h"

/* code taken from pfring_mod.c of pfring userspace library */
#define USE_MB

#define gcc_mb() __asm__ __volatile__("": : :"memory")

#if defined(__i386__) || defined(__x86_64__)
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")
#else /* other architectures (e.g. ARM) */
#define rmb() gcc_mb()
#define wmb() gcc_mb()
#endif
/* end of pfring_mod.c code */

PfSocket *pfsocket = NULL;

DnaSocket *skts[MAX_PORT + 1] = {NULL};

int find_ip(char *ifname, struct in_addr *addr) {
  struct ifaddrs * ifa_list = NULL;
  struct ifaddrs * ifa = NULL;
  getifaddrs(&ifa_list);
  for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next)
    if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, ifname) == 0) {
      memcpy(addr, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, sizeof(struct in_addr));
      break;
    }
  if (ifa_list != NULL)
    freeifaddrs(ifa_list);
  return ifa == NULL;
}

int find_mac(char *ifname, struct ether_addr *mac) {
  int s = socket(PF_INET, SOCK_STREAM, 0);
  int ret = -1;
  if (s > 0) {
    struct ifreq ifb;
    memset(&ifb, 0, sizeof(ifb));
    strncpy(ifb.ifr_name, ifname, sizeof(ifb.ifr_name));
    if ((ret=ioctl(s, SIOCGIFHWADDR, &ifb)) == 0) {
      memcpy(mac, ifb.ifr_hwaddr.sa_data, sizeof(struct ether_addr));
    }
  }
  close(s);
  return ret;
}

void pfsocket_close(PfSocket *s) {
  if (s->skt) {
    pfring_shutdown(s->skt);
    pthread_join(s->reader, NULL);
    shutdown_all_sockets();
    arp_kill(s);
#ifdef DNASTACK_DEBUG
    dnastack_stats(s);
#endif
    pfring_close(s->skt);
    free(s);
  }
}

PfSocket *pfsocket_open(char *ifname) {
  PfSocket *s = malloc(sizeof(PfSocket));
  if (s == NULL) return NULL;
  memset(s, 0, sizeof(*s));
  s->skt = pfring_open(ifname, 0, MTU, 0);
  if (s->skt == NULL                ||
      pfring_enable_ring(s->skt)    ||
      find_ip(ifname, &s->addr)     ||
      find_mac(ifname, &s->mac)     ||
      arp_init(s)                   ||
      read_init(s)) {
    pfsocket_close(s);
    return NULL;
  }
  pthread_spin_init(&s->write_lock, PTHREAD_PROCESS_PRIVATE);
  /* send spurious arp */
  send_arp_req(s->addr, s);
  return s;
}


int dnastack_init() {
  FILE *f = fopen("/etc/dnastack.conf", "r");
  pfsocket = NULL;
  if (f) {
    char ifname[18];
    if (fgets(ifname, sizeof(ifname), f)) {
      char *p = strchr(ifname, '\n');
      if (p)
	*p = '\0';
      srand(time(NULL));
#ifdef DNASTACK_DEBUG
      printf("interface: %s\n", ifname);
#endif
      pfsocket = pfsocket_open(ifname);
    }
    fclose(f);
  }
  return pfsocket == NULL;
}

int dnastack_kill() {
  if (pfsocket) {
    pfsocket_close(pfsocket);
  }
  return 0;
}

#define START_PORT 35000
DnaSocket *dnasocket_open() {
  DnaSocket *s;
  if (pfsocket == NULL) return NULL;
  s = malloc(sizeof(DnaSocket));
  if (s == NULL) return NULL;
  memset(s, 0, sizeof(DnaSocket));
  s->skt = pfsocket;
  s->id = rand();
  s->proto.proto_id = IPPROTO_UDP;
  s->proto.make_hdr = udp_make_hdr;
  s->iget_arp_cache = s->ipop_arp_cache = s->arp_cache;
  pkt_ring_init(&s->ring);
  sem_init(&s->sem, 0, 0);
  for (s->port = START_PORT; s->port < MAX_PORT && skts[htons(s->port)]; s->port++)
    ;
  if (s->port == MAX_PORT) {
    free(s);
    s = NULL;
  } else {
    s->port = htons(s->port);
    skts[s->port] = s;
  }
  return s;
}

int dnasocket_bind(const struct sockaddr_in *addr, DnaSocket *skt) {
  u_int16_t port = addr->sin_port;
  if (skts[port]) {
    errno = EADDRINUSE;
    return -1;
  }
  skts[skt->port] = NULL;
  skt->port = port;
  skts[port] = skt;
  return 0;
}

void dnasocket_stats(DnaSocket *skt) {
  printf("socket %i\n  pkt_writed -> %" PRIu64
	 "\n  pkt_zero -> %" PRIu64
	 "\n  pkt_dropped -> %" PRIu64 "\n",
	 ntohs(skt->port),
	 skt->pkt_recv,
	 skt->pkt_zero,
	 skt->pkt_drop);
}

int dnasocket_close(DnaSocket *skt) {
  skt->shutdown = 1;
  arp_send_signals(skt->skt);
  return 0;
}

void dnasocket_free(DnaSocket *skt) {
  skts[skt->port] = NULL;
  pkt_ring_free(&skt->ring);
#ifdef DNASTACK_DEBUG
  dnasocket_stats(skt);
#endif
  free(skt);
}

ssize_t dnasocket_sendto(const char *msg,
			 size_t msg_len,
			 int flags,
			 const struct sockaddr_in *addr,
			 DnaSocket *skt) {
  ssize_t ret = -1;
  skt->is_sending = 1;
  if (!skt->shutdown)
    ret = send_pkt(msg, msg_len, flags, addr, skt);
  skt->is_sending = 0;
  return ret;
}

ssize_t dnasocket_recvfrom(void *buf,
			   size_t len,
			   int flags,
			   struct sockaddr_in *src_addr, 
			   DnaSocket *skt) {
  int avoid_block = flags & MSG_DONTWAIT;
  ssize_t retlen;
  skt->is_reading = 1;
  while ((retlen=read_pkt(buf, len, src_addr, skt)) < 0 &&
	 !avoid_block &&
	 !skt->shutdown) {
    sem_wait(&skt->sem);
  }
  skt->is_reading = 0;
  if (retlen == -1 &&
      avoid_block)
    errno = EWOULDBLOCK;
  return retlen;
}

void search_closed_sockets() {
  DnaSocket **s, **end = skts + MAX_PORT;
  for (s=skts; s < end; s++)
    if (*s                &&
	(*s)->shutdown    &&
	!(*s)->is_reading &&
	!(*s)->is_sending)
      dnasocket_free(*s);
}

void shutdown_all_sockets() {
  DnaSocket **s, **end = skts + MAX_PORT;
  for (s=skts; s < end; s++) {
    if (*s) {
      dnasocket_close(*s);
      sem_post(&(*s)->sem);
    }
  }
  for (s=skts; s < end; s++) {
    if (*s) {
      while ((*s)->is_reading ||
	     (*s)->is_sending)
	usleep(1);
      dnasocket_free(*s);
    }
  }
}

int write_pkt(u_char *buffer, size_t len, struct sockaddr_in *addr, DnaSocket *skt) {
  int ret;
  if (skt->shutdown) {
    if (!skt->is_reading &&
	!skt->is_sending)
      dnasocket_free(skt);
    return -1;
  }
  if (skt->z_stat == 1) {
    skt->z_len = min((ssize_t) len, skt->z_len);
    *skt->z_addr = *addr;
    memcpy(skt->z_buffer, buffer, skt->z_len);
#ifdef USE_MB
      wmb();
#endif
    skt->z_stat = 2;
    return 1;
  }
  ret = pkt_ring_write(&skt->ring, buffer, len, addr);
  if (ret == 1)
    return skt->z_stat ? 0 : 1;
  return ret;
}

ssize_t read_pkt(void *buffer, size_t buffer_len, struct sockaddr_in *addr, DnaSocket *skt) {
  ssize_t ret;
  if (skt->z_stat == 2) {
    skt->z_stat = 0;
    return skt->z_len;
  }
  if ((ret=pkt_ring_read(&skt->ring, buffer, buffer_len, addr)) == -1 &&
      skt->z_stat == 0) {
    skt->z_len = buffer_len;
    skt->z_addr = addr;
    skt->z_buffer = buffer;
#ifdef USE_MB
      wmb();
#endif
    skt->z_stat = 1;
  }
  return ret;
}

void dnastack_stats(PfSocket *pfskt) {
  pfring_stat stat;
  if (pfring_stats(pfskt->skt, &stat) == 0) {
    printf("pfring pkt_read -> %" PRIu64
	   "\npfring pkt_drop -> %" PRIu64
	   "\npfsocket pkt_read -> %" PRIu64
	   "\npfsocket pkt_drop -> %" PRIu64
	   "\npfsocket pkt_send -> %" PRIu64
	   "\npfring pkt_drop perc -> %Lf"
	   "\npfsocket pkt_read perc -> %Lf"
	   "\npfsocket pkt_drop perc -> %Lf\n",
	   stat.recv,
	   stat.drop,
	   pfskt->pkt_recv,
	   pfskt->pkt_drop,
	   pfskt->pkt_send,
	   (long double) stat.drop / (long double) stat.recv, 
	   (long double) pfskt->pkt_recv / (long double) stat.recv,
	   (long double) pfskt->pkt_drop / (long double) pfskt->pkt_recv);
  }
}
