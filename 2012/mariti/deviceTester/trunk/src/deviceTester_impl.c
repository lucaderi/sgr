#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

/* per packetData_cmp */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "timeUtils.h"
#include "types.h"
#include "deviceTester.h"

void dt_simulate_init(void) {
  srandom(time(NULL));
}

int dt_simulate_send(pcap_t *p, const void *buf, size_t size) {
  int bytesSend;

  /* send packet */
  bytesSend = pcap_inject(p, buf, size);
  if (bytesSend != size) {
    fprintf(stderr, "WARNING: pcap_inject\n");
  }
  return bytesSend;
}

#ifndef SIMULATE_LOSTPERC 
#define SIMULATE_LOSTPERC 10
#endif
#ifndef SIMULATE_SUTMAXDELAY
#define SIMULATE_SUTMAXDELAY 100
#endif
#ifndef SIMULATE_SUTMINDELAY
#define SIMULATE_SUTMINDELAY 10
#endif

int simulate_lostperc = SIMULATE_LOSTPERC;
int simulate_sutmaxdelay = SIMULATE_SUTMAXDELAY;
int simulate_sutmindelay = SIMULATE_SUTMINDELAY;

void simulate_init(int lostperc, int sutmaxdelay, int sutmindelay) {
  simulate_lostperc = lostperc;
  simulate_sutmaxdelay = sutmaxdelay;
  simulate_sutmindelay = sutmindelay;
}

const u_char *dt_simulate_receive(pcap_t *p, struct pcap_pkthdr *h) {
  const u_char *bytes = pcap_next(p, h);
  struct timespec t, r;
  usec_t tot_delay = 0; /* milli seconds */
  int i;
  i = random();
  if (i%100 < simulate_lostperc) {
    /* sut -> packet filtered/lost */
    bytes = NULL;
#if defined DEBUG && defined DEBUG_SIMULATE
    fprintf(dbg_logfile, "-----> simulate LOST\n");
#endif
  } else {
    /* sut -> latency */
    i = random() % (simulate_sutmaxdelay-simulate_sutmindelay) + simulate_sutmindelay;	
    tot_delay += i;
#if defined DEBUG && defined DEBUG_SIMULATE
    fprintf(dbg_logfile, "------> sut-latency=%d, byte=%p, ts=%lu.%u, caplen=%u\n",
	    i, bytes, h->ts.tv_sec, h->ts.tv_usec, h->caplen);
#endif
  }
  /* sleep */
  t.tv_sec = 0; t.tv_nsec = tot_delay*1000000;
  while (-1 == nanosleep(&t, &r)) {
    t.tv_sec = r.tv_sec;
    t.tv_nsec = r.tv_nsec;
  }
  /* update pcap packet header */
  h->ts.tv_usec += tot_delay;

  return bytes;
}


unsigned char part_evenAndOdd(const u_char *bytes) {
  static unsigned char s=1;
  s = (s+1) %2;
  return s;
}

unsigned char part_evenAndOddIp(int dlt, const u_char *bytes) {
  unsigned char result;
  switch (dlt) {
  case DLT_EN10MB:
    if (ntohs( ((struct ether_header *)bytes)->ether_type ) == ETHERTYPE_IP) {
      bytes += ETHER_ADDR_LEN;
      result = (inet_lnaof(((struct ip *)bytes)->ip_src) +
		inet_netof(((struct ip *)bytes)->ip_src)) % 2;
    } else {
      result = 0;
    }
    break;
  default: result = 0;
  }
  return result;
}

unsigned char part_evenAndOddMac(int dlt, const u_char *bytes) {
  unsigned char result;
  switch (dlt) {
  case DLT_EN10MB:
    result = ((struct ether_header *)bytes)->ether_shost[ETHER_ADDR_LEN-1] %2;
    break;
  default: result = 0; 
  }
  return result;
}

unsigned char part_random(void) {
  static char s;
  if (!s) { s = 1; srandom(time(NULL)); }
  return random() %2;
}

static struct partval { char *str; unsigned char ide; } partval[] = {
  { "none", PARTRULE_NONE } , { "evenAndOdd", PARTRULE_EO } ,
  { "ip", PARTRULE_EO_IP }, { "mac", PARTRULE_EO_MAC },
  { "random", PARTRULE_RAND }, { NULL, 0 } };

unsigned char parsePartRule(const char *str) {
  int i=0;
  while (NULL != partval[i].str && strcmp(partval[i].str, str))
    i ++;
  return partval[i].ide;
}

unsigned char partitionPcapStream(int dlt, const u_char *bytes, int rule) {
  unsigned char result;
  switch (rule) {
  case PARTRULE_EO: result = part_evenAndOdd(bytes); break; 
  case PARTRULE_EO_IP: result = part_evenAndOddIp(dlt, bytes); break;
  case PARTRULE_EO_MAC: result = part_evenAndOddMac(dlt, bytes); break;
  case PARTRULE_RAND: result = part_random(); break;
  default: result = 0;
  }
  return result;
}


inline int min(int a, int b) { return(a < b ? a : b); }

int packetData_cmp(int datalinkType, const u_char *d1, unsigned int l1,
		   const u_char *d2, unsigned int l2) {
  int result = 1;

  /* Shortest ethernet packet is 60 bytes */
  if(l1 < 60) l2 = min(l1, l2);

  if (l1 != l2) {
    return 1;
  }
  switch (datalinkType) {
  case DLT_EN10MB:
    if ( ((struct ether_header *)d1)->ether_type ==
	 ((struct ether_header *)d2)->ether_type ) {
      if (ntohs( ((struct ether_header *)d1)->ether_type ) == ETHERTYPE_IP) {
	d1 += ETHER_HDR_LEN;
	d2 += ETHER_HDR_LEN;
	if (((struct ip *)d1)->ip_len == ((struct ip *)d2)->ip_len &&
	    ((struct ip *)d1)->ip_sum == ((struct ip *)d2)->ip_sum) {
	  result = 0;
	} else {
	  result = 1;
	}
      } else { 			/* no IP packet */
	result = memcmp(d1, d2, l1<l2 ? l1 : l2);
      }
    } else {			/* ET not match */
      result = 1;
    }
    break;
  default:
    result = memcmp(d1, d2, l1<l2 ? l1 : l2);
  }

  return result;
}

int parsePcapFile(struct list *list, pcap_t *offline, int partitionRule,
		  usec_t fixed_deltas) {
  const u_char	*bytes=(u_char *)1;

  while (bytes) {
    struct pcap_pkthdr	h;
    struct packet	*this;
    struct timeval	previous_ts; /* timestamp (non il delta!) del
				      * pacchetto precedente  */
    
    if (NULL == (bytes = pcap_next(offline, &h)))
      break;

    if (NULL == (this = malloc(sizeof(struct packet)))) {
      fprintf(stderr, "stop reading pcap file: not enough memory\n");
      break; 			/* eom */
    }
    if (NULL == (this->data = malloc(h.caplen))) {
      fprintf(stderr, "stop reading pcap file: not enough memory\n");
      free(this);
     break; 			/* eom */
    }
    this->next = NULL;
    this->interface =
      partitionPcapStream(pcap_datalink(offline), bytes, partitionRule);
    this->len = h.caplen;
    memcpy(this->data, bytes, h.caplen);
   
    if (!list->size) {
      list->head = this;
      list->tail = this;
      this->delta = 0;
    } else {
      list->tail->next = this;
      list->tail = this;
      if (!fixed_deltas)
	this->delta = usec_timeval_abs_sub(&h.ts, &previous_ts);
      else
	this->delta = fixed_deltas;
    } 
    previous_ts = h.ts;
    list->size ++;
  } /* end while */

  if ('\0' != *pcap_geterr(offline)) {
    return -1;
  }
  pcap_close(offline);
  return 0;
}
