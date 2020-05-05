#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "includes.h"
#include "arp.h"
#include "read.h"
#include "hashtable.h"

#define ARP_WAIT_TIME (5 * 100 * 1000 * 1000)
#define ARP_SEARCH_TIMEOUT 10
#define MAX_ARP_SEND_ATTEMPT 5
#define ARP_VALIDITY 1000 /* sec */
#define ARP_TABLE_MAX_LEN 10

struct write_kernel_stuff {
  PfSocket *pfskt;
  struct ifreq ifb;
  int sktfd;
};

int cmpElem(const void *e1, const void *e2) {
  return IPV4_CMP(&((arp_entry *) e1)->addr, &((arp_entry *) e2)->addr);
}

u_int hashElem(const void *e, u_int n) {
  return ((u_int) ((arp_entry *) e)->addr.s_addr) % n;
}

void arp_send_signals(PfSocket *skt) {
  pthread_mutex_lock(&skt->arp_cache_mutex);
  pthread_cond_signal(&skt->arp_cache_cond);
  pthread_mutex_unlock(&skt->arp_cache_mutex);
}

void arp_read_kernel_cache(PfSocket *skt) {
  FILE *f = fopen("/proc/net/arp", "rt");
  char buffer[200];
  /* skip first line  */
  if (fgets(buffer, sizeof(buffer), f)) {
    while (!feof(f)) {
      if (fgets(buffer, sizeof(buffer), f)) {
	char ip[INET6_ADDRSTRLEN + 1];
	int type, flags;
	char hw[18];
	char mask[sizeof(ip)];
	char dev[16];
	int num = sscanf(buffer, "%39s 0x%x 0x%x %17s %39s %16s\n",
			 ip, &type, &flags, hw, mask, dev);
	if (num != 6)
	  continue;
	if (strcmp(dev, skt->skt->device_name) == 0 &&
	    type == 1 &&
	    strcmp(mask, "*") == 0) {
	  struct in_addr addr;
	  struct ether_addr *mac = ether_aton(hw);
	  if (inet_pton(AF_INET, ip, &addr) && mac) {
	    arp_put(*mac, addr, 1, skt);
	  }
	}
      }
    }
  }
  fclose(f);
}

void arp_write_kernel_cache(const void *entry, const void *obj) {
  arp_entry *e = (arp_entry *) entry;
  struct write_kernel_stuff *stuff = (struct write_kernel_stuff *) obj;
  struct arpreq req;
  struct sockaddr_in addr, netmask;
  memset(&req, 0, sizeof(req));

  netmask.sin_family = AF_INET;
  netmask.sin_port = 0xffff;
  netmask.sin_addr.s_addr = INADDR_ANY;
  memcpy(&req.arp_netmask, &netmask, sizeof(netmask)); 

  req.arp_flags = ATF_COM;

  strcpy(req.arp_dev, stuff->pfskt->skt->device_name);

  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr = e->addr;
  memcpy(&req.arp_pa, &addr, sizeof(addr));

  memcpy(stuff->ifb.ifr_hwaddr.sa_data, &e->mac, sizeof(struct ether_addr));
  memcpy(&req.arp_ha, &stuff->ifb.ifr_hwaddr, sizeof(struct sockaddr));

  ioctl(stuff->sktfd, SIOCSARP, &req);
}

int arp_init(PfSocket *skt) {
  skt->n_arp_readers = 0;
  skt->shutdown_arp = 0;
  skt->arp_table = hashtable_new(ARP_TABLE_MAX_LEN, cmpElem, hashElem);
  if (!skt->arp_table)
    return -1;
  pthread_mutex_init(&skt->arp_cache_mutex, NULL);
  pthread_cond_init(&skt->arp_cache_cond, NULL);
  arp_read_kernel_cache(skt);
  return 0;  
}

int arp_kill(PfSocket *skt) {
  if (skt->arp_table) {
    struct write_kernel_stuff stuff;
    stuff.pfskt = skt;
    stuff.sktfd = socket(AF_INET, SOCK_STREAM, 0);
    pthread_mutex_lock(&skt->arp_cache_mutex);
    skt->shutdown_arp = 1;
    if (stuff.sktfd > 0) {
      memset(&stuff.ifb, 0, sizeof(stuff.ifb));
      strncpy(stuff.ifb.ifr_name, skt->skt->device_name, sizeof(stuff.ifb.ifr_name));
      if (ioctl(stuff.sktfd, SIOCGIFHWADDR, &stuff.ifb) == 0)
	hashtable_map(skt->arp_table, arp_write_kernel_cache, &stuff);
      close(stuff.sktfd);
    }
    hashtable_free(skt->arp_table, free);
    pthread_mutex_unlock(&skt->arp_cache_mutex);
  }
  return 0;
}

int arp_get_table(arp_entry *entry, struct in_addr addr, PfSocket *skt) {
  const arp_entry *e = NULL;
  time_t start = time(NULL), timeout = start + ARP_SEARCH_TIMEOUT;
  arp_entry k;
  k.addr = addr;
  while ( (e=hashtable_get(skt->arp_table, &k)) == NULL ||
	  e->timeout < time(NULL) ) {
    struct timespec ts;
    time_t remain = timeout - time(NULL);
    if (e)
      free(hashtable_pop(skt->arp_table, &k));
    if (remain <= 0 ||
	send_arp_req(addr, skt))
      return -1;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += ARP_WAIT_TIME;
    pthread_cond_timedwait(&skt->arp_cache_cond, &skt->arp_cache_mutex, &ts);
  }
  if (e)
    *entry = *e;
  return e == NULL;
}

int arp_get(struct ether_addr *mac, struct in_addr addr, DnaSocket *skt) {
  int ret;
  arp_entry *cache_end = skt->arp_cache + ARP_CACHE_LEN;
  arp_entry *p = skt->iget_arp_cache, *end = cache_end;
  time_t now = time(NULL);
  PfSocket *pfskt = skt->skt;
  for (;;) {
    for (; p < end; p++)
      if (IPV4_CMP(&p->addr, &addr) == 0 &&
	  p->timeout > now) {
	*mac = p->mac;
	skt->iget_arp_cache = p;
	return 0;
      }
    if (p == skt->iget_arp_cache)
      break;
    end = skt->iget_arp_cache;
    p   = skt->arp_cache;
  }
  pthread_mutex_lock(&pfskt->arp_cache_mutex);
  pfskt->n_arp_readers++;
  ret = arp_get_table(skt->ipop_arp_cache, addr, pfskt);
  pfskt->n_arp_readers--;
  pthread_mutex_unlock(&pfskt->arp_cache_mutex);
  if (ret)
    return ret;
  *mac = skt->ipop_arp_cache->mac;
  skt->iget_arp_cache = skt->ipop_arp_cache++; /* next time it will start to search from here */
  if (skt->ipop_arp_cache == cache_end)
    skt->ipop_arp_cache = skt->arp_cache;
  return 0;
}

int entry_timeout(void *e, void *unuseful_ptr) {
  arp_entry **unuseful = (arp_entry **) unuseful_ptr;
  int ret = ((arp_entry *) e)->timeout <= time(NULL);
  if (ret)
    free(e);
  if (!(*unuseful) || ((arp_entry *) e)->last_used < (*unuseful)->last_used)
    *unuseful = (arp_entry *) e;
  return ret;
}

int arp_put(struct ether_addr mac, struct in_addr addr, int unlock, PfSocket *skt) {
  arp_entry *old;
  arp_entry *e = malloc(sizeof(arp_entry));
  int ret;
  if (e == NULL) {
    errno = ENOMEM;
    return -1;
  }
  e->addr = addr;
  e->mac = mac;
  e->last_used = time(NULL);
  e->timeout = e->last_used + ARP_VALIDITY;
  pthread_mutex_lock(&skt->arp_cache_mutex);
  ret = hashtable_put(skt->arp_table, e, (const void **) &old);
  switch (ret) {
  case 1:
    free(old);
    pthread_cond_signal(&skt->arp_cache_cond);
    break;
  case 0:
    if (hashtable_count(skt->arp_table) > ARP_TABLE_MAX_LEN) {
      arp_entry *most_unuseful = NULL;
      if (!hashtable_remove(skt->arp_table, entry_timeout, (void *) &most_unuseful)) {
	free(hashtable_pop(skt->arp_table, most_unuseful));
      }
    }
    pthread_cond_signal(&skt->arp_cache_cond);
    break;
  case -1:
    free(e);
  }
  if (unlock)
    pthread_mutex_unlock(&skt->arp_cache_mutex);
  return ret < 0 ? -1 : 0;
}

struct ether_addr mac_broadcast = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
struct ether_addr mac_null = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };

int send_arp(struct in_addr dest_addr,
	     struct ether_addr mac_ether,
	     struct ether_addr mac_arp,
	     u_int16_t op,
	     PfSocket *skt) {
  char buffer[ETHER_HDR_LEN + ARP_HDR_LEN];
  struct ether_header *eth = (struct ether_header *) buffer;
  struct arphdr *arp = (struct arphdr *) &buffer[ETHER_HDR_LEN];
  char *p = ((char *) &arp->ar_op) + 2;
  int ret;
  /* ETHERNET */
  MAC_CPY(&eth->ether_dhost, &mac_ether);  /* destination mac address   */
  MAC_CPY(&eth->ether_shost, &skt->mac);   /* source mac address        */
  eth->ether_type  = htons(ETHERTYPE_ARP); /* upper level protocol type */
  /* ARP */
  arp->ar_hrd = htons(ARPHRD_ETHER);       /* hardware address type     */
  arp->ar_pro = htons(ETHERTYPE_IP);       /* protocol address type     */
  arp->ar_hln = ETH_ALEN;                  /* hardware address len      */
  arp->ar_pln = IPV4_LEN;                  /* protocol address len      */
  arp->ar_op  = htons(op);                 /* arp operation type        */
  STORE_MAC(p, &skt->mac);                 /* sender mac address        */
  STORE_IPV4(p, &skt->addr);               /* sender ip address         */
  STORE_MAC(p, &mac_arp);                  /* target mac address        */
  STORE_IPV4(p, &dest_addr);               /* target ip address         */

  /* send packet */
  pthread_spin_lock(&skt->write_lock);
  ret = pfring_send(skt->skt, buffer, sizeof(buffer), 1) != sizeof(buffer);
  pthread_spin_unlock(&skt->write_lock);
  return ret;
}

int send_arp_req(struct in_addr dest_addr, PfSocket *skt) {
  return send_arp(dest_addr, mac_broadcast, mac_null, ARPOP_REQUEST, skt);
}
int send_arp_reply(struct in_addr dest_addr,
		  struct ether_addr dest_mac,
		  PfSocket *skt) {
  return send_arp(dest_addr, dest_mac, dest_mac, ARPOP_REPLY, skt);
}
