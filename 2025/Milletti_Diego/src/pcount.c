/*
 *
 * Prerequisite
 * sudo apt-get install gcc
 * sudo apt-get install libpcap-dev
 *
 * Compilation
 * gcc pcount -o pcount.c ndpifun.c -lpcap -lm
 * 
 * Execution
 * sudo ./pcount -i <file.pcap> -v 1 (-r filename.txt)
 *
*/

#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd;
int verbose = 0;
struct pcap_stat pcapStats;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <math.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>     /* the L2 protocols */


#include <inttypes.h>
#include "header.h"

#define MIN_PACKETS_FOR_ANALYSIS 15

typedef struct {
  uint8_t is_ipv6; // IPv4 = 0, IPv6 = 1
  union {
    struct {
      uint32_t ip_src; // uint32_t == struct in_addr
      uint32_t ip_dst;
    } ipv4;
    struct {
      struct in6_addr ip_src;
      struct in6_addr ip_dst;
    } ipv6;
  };
  uint16_t port_src;
  uint16_t port_dst;
} FlowKey; // Struttura per identificare univocamente un flusso TCP

typedef struct {
    FlowKey key;
    struct ndpi_analyze_struct *win_stats;
    int packet_count;
    int zero_window_count;
} FlowData; // Struttura per l'intero flusso TCP

FlowData *all_flows = NULL;
int flow_count = 0; // Numero totale di flussi
int flow_capacity = 0; // Capacità del flusso

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;


FILE *report_file = NULL; // Inizializzazione file di report
char *report_path = NULL;

// Macro per scrivere l'output del programma su un file di testo
// lo slash serve per dire che la macro continua alla riga successiva.
// do-while(0) per trattare le macro multi riga come un'unica istruzione, per evitare di confondere più else
#define out(...) do { \
  if(report_file) fprintf(report_file, __VA_ARGS__); \
  else printf(__VA_ARGS__); \
} while (0)

/* *************************************** */

int compare_keys(FlowKey* a, FlowKey* b){ // Confronto due FlowKey
  if(a->is_ipv6 != b->is_ipv6) return 0;

  if(!a->is_ipv6){
    return (a->ipv4.ip_src == b->ipv4.ip_src &&
            a->ipv4.ip_dst == b->ipv4.ip_dst &&
            a->port_src == b->port_src &&
            a->port_dst == b->port_dst);
  } else {
    return (memcmp(&a->ipv6.ip_src, &b->ipv6.ip_src, sizeof(struct in6_addr)) == 0 &&
            memcmp(&a->ipv6.ip_dst, &b->ipv6.ip_dst, sizeof(struct in6_addr)) == 0 &&
            a->port_src == b->port_src &&
            a->port_dst == b->port_dst);
  }
}

/* *************************************** */

int match_flow_bidir(FlowKey* a, FlowKey* b){
  if(a->is_ipv6 != b->is_ipv6) return 0;

  if(!a->is_ipv6){
    return ((a->ipv4.ip_src == b->ipv4.ip_src && a->ipv4.ip_dst == b->ipv4.ip_dst &&
            a->port_src == b->port_src && a->port_dst == b->port_dst) ||
            (a->ipv4.ip_src == b->ipv4.ip_dst && a->ipv4.ip_dst == b->ipv4.ip_src &&
            a->port_src == b->port_dst && a->port_dst == b->port_src));
  } else {
    return ((memcmp(&a->ipv6.ip_src, &b->ipv6.ip_src, sizeof(struct in6_addr)) == 0 &&
            memcmp(&a->ipv6.ip_dst, &b->ipv6.ip_dst, sizeof(struct in6_addr)) == 0 &&
            a->port_src == b->port_src && a->port_dst == b->port_dst) ||
            (memcmp(&a->ipv6.ip_src, &b->ipv6.ip_dst, sizeof(struct in6_addr)) == 0 &&
            memcmp(&a->ipv6.ip_src, &b->ipv6.ip_dst, sizeof(struct in6_addr)) == 0 &&
            a->port_src == b->port_dst && a->port_dst == b->port_src));
  }
}

/* *************************************** */

FlowData* get_or_create_flow(FlowKey* key){
    for(int i=0; i<flow_count; i++){
        if(compare_keys(&all_flows[i].key,key)){
            return &all_flows[i];
        }
    }

    // Allocazione dinamica del flusso
    if(flow_count >= flow_capacity){
      int new_cap = (flow_capacity == 0) ? 128 : flow_capacity * 2;
      FlowData *tmp = realloc(all_flows, new_cap * sizeof(FlowData));
      if(!tmp){
        perror("realloc allflows");
        exit(EXIT_FAILURE);
      }
      all_flows = tmp;
      flow_capacity = new_cap;
    }

    // Inizializzazione del nuovo flusso (se non già esistente)
    FlowData *new_flow = &all_flows[flow_count++];
    new_flow->key = *key;
    new_flow->packet_count = 0;
    new_flow->zero_window_count = 0;
    new_flow->win_stats = ndpi_alloc_data_analysis(128);  // Usa sliding window di 128 valori per un risparmio della memoria

    return new_flow;
}

/* *************************************** */

int32_t gmt_to_local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

char* format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals)	{
  u_int a1 = ((u_long)val / 1000000000) % 1000;	
  u_int a = ((u_long)val / 1000000) % 1000;
  u_int b = ((u_long)val / 1000) % 1000;
  u_int c = (u_long)val % 1000;
  u_int d = (u_int)((val - (u_long)val)*100) % 100;

  if(add_decimals) {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else
      snprintf(buf, buf_len, "%.2f", val);
  } else {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else
      snprintf(buf, buf_len, "%u", (unsigned int)val);
  }

  return(buf);
}

/* *************************************** */

int drop_privileges(const char *username) {
  struct passwd *pw = NULL;

  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return -1;
  }

  pw = getpwnam(username);

  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  if(pw != NULL) {
    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
      fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
      return -1;
    } else {
      fprintf(stderr, "user changed to %s\n", username);
    }
  } else {
    fprintf(stderr, "unable to locate user %s\n", username);
    return -1;
  }

  umask(0);
  return 0;
}

/* *************************************** */
/*
 * The time difference in microseconds
 */
long delta_time (const struct timeval * now,
                 const struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

void print_stats() {
  struct pcap_stat pcapStat;
  struct timeval endTime;
  float deltaSec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;
  char buf1[64], buf2[64];

  if(startTime.tv_sec == 0) {
    lastTime.tv_sec = 0;
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

  if(pcap_stats(pd, &pcapStat) >= 0) {
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

    if(lastTime.tv_sec > 0) {
      deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
      diff = numPkts-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
	      format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	      format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
      lastPkts = numPkts;
    }

    fprintf(stderr, "=========================\n");
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  pcap_breakloop(pd);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* __intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char* intoa(unsigned int addr) {
  return(__intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static inline char* in6toa(struct in6_addr addr6) {
  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h, //h: timestamp, numero di byte effettivi e lunghezza del pacchetto 
			 const u_char *p) { //p: puntatore ai dati grezzi
        
  // printf("pcap_sendpacket returned %d\n", pcap_sendpacket(pd, p, h->caplen));
  struct ether_header ehdr;
  struct ip *ip_hdr;
  struct tcphdr *tcp_hdr;

  uint16_t eth_type;

  memcpy(&ehdr, p, sizeof(struct ether_header)); // Copia dei 14 byte header ethernet

  eth_type = ntohs(ehdr.ether_type); // Estrae il tipo di protocollo incapsulato nell'ethernet frame (es.IPv4 0x0800, IPv6 0x86DD)
  
  if(eth_type == 0x800){ // Solo indirizzi IPv4
    ip_hdr = (struct ip *)(p + sizeof(struct ether_header)); // Header IPv4
    
    if(ip_hdr->ip_p == IPPROTO_TCP){ // Controllo se il protoccolo è TCP
      int ip_header_len = ip_hdr->ip_hl * 4; // Lunghezza header IPv4

      tcp_hdr = (struct tcphdr *)(p + sizeof(struct ether_header) + ip_header_len); // Header TCP

      uint16_t window = ntohs(tcp_hdr->th_win); // Network byte order (big endian) to host byte order (little endian)

      FlowKey key;
      key.is_ipv6 = 0;
      key.ipv4.ip_src = ip_hdr->ip_src.s_addr;
      key.ipv4.ip_dst = ip_hdr->ip_dst.s_addr;
      key.port_src = ntohs(tcp_hdr->th_sport);
      key.port_dst = ntohs(tcp_hdr->th_dport);

      FlowData *flow = get_or_create_flow(&key);

      flow->packet_count++;
      if(window == 0){
        flow->zero_window_count++;
      }
      ndpi_data_add_value(flow->win_stats, (u_int64_t)window);

      //stampa info preliminare
      char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(ip_hdr->ip_src), src, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst, INET_ADDRSTRLEN);
      printf("Flusso IPv4 %s:%d -> %s:%d | Finestra: %u\n",
            src, ntohs(tcp_hdr->th_sport),
            dst, ntohs(tcp_hdr->th_dport),
            window);

    }
  }
  if(eth_type == 0x86DD){ // Solo indirizzi IPv6
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(p + sizeof(struct ether_header)); // Header IPv6 (40 byte)

    if(ip6_hdr->ip6_nxt == IPPROTO_TCP){
      struct tcphdr *tcp_hdr = (struct tcphdr *)(ip6_hdr + 1); // TCP header che si trova dopo l'header classico IPv6

      uint16_t window = ntohs(tcp_hdr->th_win); // Estraggo dimensione della finestra

      FlowKey key;
      key.is_ipv6 = 1;
      key.ipv6.ip_src = ip6_hdr->ip6_src;
      key.ipv6.ip_dst = ip6_hdr->ip6_dst;
      key.port_src = ntohs(tcp_hdr->th_sport);
      key.port_dst = ntohs(tcp_hdr->th_dport);

      FlowData *flow = get_or_create_flow(&key);

      flow->packet_count++;
      if(window == 0){
        flow->zero_window_count++;
      }

      ndpi_data_add_value(flow->win_stats, (u_int64_t)window);

      // Stampa info preliminare IPv6
      char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src, sizeof(src)); // Conversione da IPv6 binario a stringa
      inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst, sizeof(dst));
      printf("Flusso IPv6 %s:%d → %s:%d | Finestra: %u\n",
            src, ntohs(tcp_hdr->th_sport),
            dst, ntohs(tcp_hdr->th_dport),
            window);
    }
  }
  if (numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++, numBytes += h->len;
 }

/* *************************************** */


void flow_analysis(){
  out("\n======= ANALISI FLUSSI TCP =======\n");

  int *printed = calloc(flow_count, sizeof(int));

  for(int i=0;i<flow_count;i++){
    if(printed[i]) continue;

    FlowData* fwd = &all_flows[i];

    // Cerco la direzione opposta
    FlowData *rev = NULL;
    for(int j=i+1;j<flow_count;j++){
      if(match_flow_bidir(&fwd->key,&all_flows[j].key)){
        rev = &all_flows[j];
        printed[j] = 1;
        break;
      }
    }

    // Imposto il flusso [i] come già stampato
    printed[i] = 1;
    
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

    if (fwd->key.is_ipv6) {
        inet_ntop(AF_INET6, &fwd->key.ipv6.ip_src, src, sizeof(src));
        inet_ntop(AF_INET6, &fwd->key.ipv6.ip_dst, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET, &fwd->key.ipv4.ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &fwd->key.ipv4.ip_dst, dst, sizeof(dst));
    }
    out("╔══════════════════════════════════════════════════════════════╗\n");
    out("║Flusso %s:%d ⇄ %s:%d\n",
    src, fwd->key.port_src,
    dst, fwd->key.port_dst);
    out("╚══════════════════════════════════════════════════════════════╝\n");

    // Analisi fwd
    float avg = ndpi_data_mean(fwd->win_stats);
    float dev_std = ndpi_data_stddev(fwd->win_stats);
    u_int64_t min = ndpi_data_min(fwd->win_stats);
    u_int64_t max = ndpi_data_max(fwd->win_stats);

    out("→ Direzione %s → %s\n", src, dst);

    if(fwd->packet_count < MIN_PACKETS_FOR_ANALYSIS){
      out("[!] Troppi pochi pacchetti per un'analisi affidabile [!]\n");
    }

    out("  Pacchetti: %d\n", fwd->packet_count);

    out("  Finestra [min: %" PRIu64 ", max: %" PRIu64 ", media: %.2f]\n", min, max, avg);

    if(fwd->zero_window_count > 0){
      out("  ⚠ Anomalia ⚠ : dimensione finestra TCP uguale a zero (%d volte)\n", fwd->zero_window_count);
    }

    // Anomalia se supera 18.000 (valore trovato dalle diverse prove effuttuate catturando flussi) e se la dvstd supera il 70% della media -> "coefficente di variazione" (per evitare falsi allarmi su finestre alte e stabili)
    if(dev_std > 18000.0 && dev_std > 0.7 * avg && fwd->packet_count > MIN_PACKETS_FOR_ANALYSIS){
      out("  ⚠ Anomalia ⚠ : Forti oscillazioni della finestra TCP (dev_std=%.2f)\n", dev_std);
    } else if(dev_std > 10000.0 && dev_std > 0.7 * avg && fwd->packet_count > MIN_PACKETS_FOR_ANALYSIS){
      out("  Oscillazioni moderate della finestra TCP (dev_std=%.2f)\n", dev_std);
    }

    if(rev){
      char src2[INET6_ADDRSTRLEN], dst2[INET6_ADDRSTRLEN];

      if (rev->key.is_ipv6) {
          inet_ntop(AF_INET6, &rev->key.ipv6.ip_src, src2, sizeof(src2));
          inet_ntop(AF_INET6, &rev->key.ipv6.ip_dst, dst2, sizeof(dst2));
      } else {
          inet_ntop(AF_INET, &rev->key.ipv4.ip_src, src2, sizeof(src2));
          inet_ntop(AF_INET, &rev->key.ipv4.ip_dst, dst2, sizeof(dst2));
      }

      // Analisi rev
      avg = ndpi_data_mean(rev->win_stats);
      dev_std = ndpi_data_stddev(rev->win_stats);
      min = ndpi_data_min(rev->win_stats);
      max = ndpi_data_max(rev->win_stats);

      out("\n→ Direzione %s → %s\n", src2, dst2);

      if(rev->packet_count < MIN_PACKETS_FOR_ANALYSIS){
        out("[!] Troppi pochi pacchetti per un'analisi affidabile [!]\n");
      }

      out("  Pacchetti: %d\n", rev->packet_count);
      out("  Finestra [min: %" PRIu64 ", max: %" PRIu64 ", media: %.2f]\n", min, max, avg);

      if(rev->zero_window_count > 0){
        out("  ⚠ Anomalia ⚠ : dimensione finestra TCP uguale a zero (%d volte)\n", rev->zero_window_count);
      }

      // Anomalia se supera 18.000 e se la dvstd supera il 70% della media
      if(dev_std > 18000.0 && dev_std > 0.7 * avg && rev->packet_count > MIN_PACKETS_FOR_ANALYSIS){
        out("  ⚠ Anomalia ⚠ : Forti oscillazioni della finestra TCP (dev_std=%.2f)\n", dev_std);
      } else if(dev_std > 10000.0 && dev_std > 0.7 * avg && fwd->packet_count > MIN_PACKETS_FOR_ANALYSIS){
        out("  Oscillazioni moderate della finestra TCP (dev_std=%.2f)\n", dev_std);
      }
    }

    out("----------------------------------------------------------------\n");
  }
  free(printed);
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-f <filter>      [pcap filter]\n");
  printf("-w <path>        [pcap write file]\n");  
  printf("-l <len>         [Capture length]\n");
  printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");
  printf("-r <file> [save the report in a txt file]\n");


  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    printf("\nAvailable devices (-i):\n");
    while(devpointer) {
      const char *descr = devpointer->description;

      if(descr)
	printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
      else
	printf(" %d. %s\n", i++, devpointer->name);
      
      devpointer = devpointer->next;
    }
  }
}

/* *************************************** */

// Libero memoria allocata
void cleanup_flows(){
  for(int i=0;i<flow_count;i++){
    ndpi_free_data_analysis(all_flows[i].win_stats, 1); // Con parametro 1 libera anche il puntatore
  }
  free(all_flows);

  if(report_path){
    free(report_path);
    report_path = NULL;
  }

}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *bpfFilter = NULL;
  char *default_filter = "tcp"; // Settato filtro TCP come default
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  struct stat s;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc, argv, "hi:l:v:f:w:r:")) != '?') {
    if((c == 255) || (c == (u_char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    case 'i':
      device = strdup(optarg);
      break;

    case 'l':
      snaplen = atoi(optarg);
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'w':
      dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg);
      if(dumper == NULL) {
        printf("Unable to open dump file %s\n", optarg);
        return(-1);
      }
      break;

    case 'f':
      bpfFilter = strdup(optarg);
      break;

    //aggiunto case "r" per indirizzare l'output su un file .txt
    case 'r':
      report_path = strdup(optarg);
      break;
    }
  }

  if(report_path != NULL){
    report_file = fopen(report_path, "w");
    if(!report_file){
      perror("Errore apertura file report");
      return -1;
    } else {
      printf("Report salvato in: %s\n",report_path);
    }
  }
  
  if(geteuid() != 0) {
    printf("Please run this tool as superuser\n");
    return(-1);
  }
  
  if(device == NULL) {
    printf("ERROR: Missing -i\n");    
    printHelp();
    return(-1);  
  }

  printf("Capturing from %s\n", device);

 if(stat(device, &s) == 0) {
    /* Device is a file on filesystem */
    if((pd = pcap_open_offline(device, errbuf)) == NULL) {
      printf("pcap_open_offline: %s\n", errbuf);
      return(-1);
    }
 } else {
    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1;
    if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
  }
 
if(bpfFilter == NULL) { // Applicazione filtro TCP come default
    bpfFilter = default_filter;
    printf("Filtro di default applicato: %s\n",bpfFilter);
}
if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) { // Programma di filtro BPF (compilato)
    printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
} else {
    if(pcap_setfilter(pd, &fcode) < 0) { // Applicazione del filtro
      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
    }
}

  if(drop_privileges("nobody") < 0)
    return(-1);
  
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }
  
  pcap_loop(pd, -1, dummyProcesssPacket, NULL);

  print_stats();

  pcap_close(pd);

  if(dumper)
    pcap_dump_close(dumper);

  // Stampo i risultati dell'analisi
  flow_analysis();

  // Libero memoria
  cleanup_flows();

  // "Free" effettuata dalla perdita di 14 byte, segnalata su Valgrind
  if(device){
    free(device);
    device = NULL;
  }

  if(report_file) fclose(report_file);
  
  return(0);
}
