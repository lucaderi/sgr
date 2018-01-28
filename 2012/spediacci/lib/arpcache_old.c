#include <pthread.h>
#include <unistd.h>
#include <net/if_arp.h>

#include "includes.h"

#define ANNOYING_SLEEP 5
#define MAX_ARP_SEND_ATTEMPT 5

void *cache = NULL;
pthread_mutex_t cache_mutex;
pthread_cond_t cache_cond;
int n_cache_readers;
pthread_t annoying_thread;
pthread_cond_t annoying_cond;

#define ARP_PKT_QUEUE_LEN 10
#define ARP_PKT_LEN ETHERNET_HDR_LEN + ARP_HDR_LEN

char *arp_pkgs[ARP_PKT_QUEUE_LEN];
int ipop, iput;
pthread_mutex_t arp_pkgs_mutex;
pthread_cond_t arp_pkgs_cond;
pthread_t arp_pkg_thread;

typedef struct {
  struct inet_addr addr;
  u_int8_t *mac;
} elem_t;

int cmpAddr(struct inet_addr *addr, elem_t *e) {
  return memcmp(addr, e->addr, sizeof(struct inet_addr));
}

void *annoying_loop(void *arg) {
  for(;;) {
    pthread_mutex_lock(&arp_pkgs_mutex);
    while (!n_cache_readers)
      pthread_cond_wait(&annoying_cond, &arp_pkgs_mutex);
    pthread_mutex_unlock(&arp_pkgs_mutex);
    sleep(ANNOYING_SLEEP);
    pthread_cond_signal(&cache_cond);
  }
}

void *arp_pkg_loop(void *arg) {
  for(;;) {
    char *pkg = arp_pkg_pop();
    struct iphdr *ip = (struct iphdr *) (pkg + ETH_HDR_SIZE);
    if (ip->version == 4 &&
	ip->tot_len == IPV4_HDR_SIZE + ARP_HDR_SIZE &&
	ip->frag_off == 0 &&
	ip->ttl > 0 &&
	ip->protocol == ARP_PROTO &&
	(ipv4_checksum((char*) ip) ^ ip->check) == 0xffff) {
      struct arphdr *arp = (struct arphdr *) (pkg + ETH_HDR_SIZE + ip->ihl * 4);
      if (arp->ar_hrd == ETH_PROTO &&
	  arp->ar_pro == IPV4_PROTO &&
	  arp->ar_hln == ETH_ALEN &&
	  arp->ar_pln == IPV4_LEN) {
	switch (arp->ar_op) {
	case ARP_REQ:
	case ARP_RESP:
	}
      }
    } 
  }
}

int arp_init() {
  ipop = ipull = 0;
  n_cache_readers = 0;
  pthread_mutex_init(&cache_mutex, NULL);
  pthread_cond_init(&cache_cond, NULL);
  pthread_mutex_init(&arp_pkg_mutex, NULL);
  pthread_cond_init(&arp_pkg_cond, NULL);
  pthread_cond_init(&annoying_cond, NULL);
  if (pthread_create(&annoying_thread, NULL, &annoying_loop, NULL))
    return -1;
  pthread_detach(annoying_thread);
  if (pthread_create(&arp_pkg_thread, NULL, &arp_pkg_loop, NULL))
    return -1;
  pthread_detach(arp_pkg_thread);
  return 0;  
}

int arp_get(u_int8_t *mac[MAC_SIZE], DnaSocket *skt) {
  elem_t *e;
  pthread_mutex_lock(&cache_mutex);
  n_cache_readers++;
  pthread_cond_signal(&annoying_cond);
  while ( (e=tfind(&skt->dest_addr, &cache, cmpAddr)) ) {
    int a;
    for (a = 0; a < MAX_ARP_SEND_ATTEMPT && send_arp_req(skt); a++)
      ;
    if (a == MAX_ARP_SEND_ATTEMPT) return -1;
    pthread_cond_wait(&cache_cond, &cache_mutex);
  }
  MAC_CPY(mac, e->mac);
  n_cache_readers--;
  pthread_mutex_unlock(&cache_mutex);
  return 0;
}

int arp_pkg_insert(char *pkt) {
  int i;
  pthread_mutex_lock(&arp_pkgs_mutex);
  i = (ipull + 1) % ARP_PKT_QUEUE_LEN;
  if (i != ipop) {
    arp_pkgs[iput] = pkt;
    iput = i;
  }
  pthread_cond_signal(&arp_pkgs_cond);
  pthread_unlock(&arp_pkgs_mutex);
  return i != ipop;
}

char *arp_pkg_pop() {
  char *p;
  pthread_mutex_lock(&arp_pkgs_mutex);
  while (ipop == iput)
    pthread_cond_wait(&arp_pkgs_cond, &arp_pkgs_mutex);
  p = arp_pkgs_cond[ipop];
  ipop = (ipop + 1) % ARP_PKT_QUEUE_LEN;
  pthread_mutex_unlock(&arp_pkgs_mutex);
  return p;
}
