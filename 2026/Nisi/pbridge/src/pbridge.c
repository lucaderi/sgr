/*
 *
 * pbridge.c - L2 network bridge using libpcap
 * Based on pcount.c (capture/stats) and psend.c (pcap_inject)
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pbridge.c -o pbridge -lpcap
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

#define ALARM_SLEEP     1
#define DEFAULT_SNAPLEN 65535   /* full packet needed for bridging */

/* Two pcap handles, one per interface */
pcap_t *pd_in  = NULL;  /* -i */
pcap_t *pd_out = NULL;  /* -o */

int verbose = 0;
static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
volatile sig_atomic_t keep_running = 1;

#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

/* *************************************** */
/* Utility functions — from pcount.c       */
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
       (loc->tm_min  - gmt->tm_min)  * 60;

  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;
  return (dt);
}

char* format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals) {
  u_int a1 = ((u_long)val / 1000000000) % 1000;
  u_int a  = ((u_long)val / 1000000)    % 1000;
  u_int b  = ((u_long)val / 1000)       % 1000;
  u_int c  = (u_long)val % 1000;
  u_int d  = (u_int)((val - (u_long)val) * 100) % 100;

  if(add_decimals) {
    if(val >= 1000000000)    snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
    else if(val >= 1000000)  snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
    else if(val >= 1000)     snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    else                     snprintf(buf, buf_len, "%.2f", val);
  } else {
    if(val >= 1000000000)    snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
    else if(val >= 1000000)  snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
    else if(val >= 1000)     snprintf(buf, buf_len, "%u'%03u", b, c);
    else                     snprintf(buf, buf_len, "%u", (unsigned int)val);
  }
  return(buf);
}

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

long delta_time(struct timeval *now, struct timeval *before) {
  time_t delta_seconds      = now->tv_sec  - before->tv_sec;
  time_t delta_microseconds = now->tv_usec - before->tv_usec;

  if(delta_microseconds < 0) {
    delta_microseconds += 1000000;
    --delta_seconds;
  }
  return((delta_seconds * 1000000) + delta_microseconds);
}

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
  deltaSec = (double)delta_time(&endTime, &startTime) / 1000000;

  fprintf(stderr, "=========================\n");
  fprintf(stderr, "Forwarded: %llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
          numPkts, (double)numPkts / deltaSec,
          numBytes, (double)8 * numBytes / (double)(deltaSec * 1000000));

  if(pcap_stats(pd_in, &pcapStat) >= 0)
    fprintf(stderr, "[in]  rcvd=%u dropped=%u\n", pcapStat.ps_recv, pcapStat.ps_drop);
  if(pcap_stats(pd_out, &pcapStat) >= 0)
    fprintf(stderr, "[out] rcvd=%u dropped=%u\n", pcapStat.ps_recv, pcapStat.ps_drop);

  if(lastTime.tv_sec > 0) {
    deltaSec = (double)delta_time(&endTime, &lastTime) / 1000000;
    diff = numPkts - lastPkts;
    fprintf(stderr, "=========================\n"
            "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
            format_numbers(diff,   buf1, sizeof(buf1), 0), deltaSec * 1000,
            format_numbers((double)diff / (double)deltaSec, buf2, sizeof(buf2), 1));
    lastPkts = numPkts;
  }

  fprintf(stderr, "=========================\n");
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp = buf;

  if ((j = *ep >> 4) != 0) *cp++ = hex[j]; else *cp++ = '0';
  *cp++ = hex[*ep++ & 0xf];
  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0) *cp++ = hex[j]; else *cp++ = '0';
    *cp++ = hex[*ep++ & 0xf];
  }
  *cp = '\0';
  return(buf);
}

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
      if (byte > 0) *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);
  retStr = (char*)(cp+1);
  return(retStr);
}

static char addrbuf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char* intoa(unsigned int addr) {
  return(__intoa(addr, addrbuf, sizeof(addrbuf)));
}

static inline char* in6toa(struct in6_addr addr6) {
  snprintf(addrbuf, sizeof(addrbuf),
           "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           addr6.s6_addr[0],  addr6.s6_addr[1],  addr6.s6_addr[2],  addr6.s6_addr[3],
           addr6.s6_addr[4],  addr6.s6_addr[5],  addr6.s6_addr[6],  addr6.s6_addr[7],
           addr6.s6_addr[8],  addr6.s6_addr[9],  addr6.s6_addr[10], addr6.s6_addr[11],
           addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14], addr6.s6_addr[15]);
  return(addrbuf);
}

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

/* *************************************** */
/* Signal handlers                         */
/* *************************************** */

void sigproc(int sig) {
  fprintf(stderr, "Leaving...\n");
  keep_running = 0;   /* main select loop will exit on next iteration */
}

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */
/* Bridge logic                            */
/* *************************************** */

struct bridge_ctx {
  pcap_t     *src;
  pcap_t     *dst;
  const char *src_name;
  const char *dst_name;
  int32_t     thiszone;
};

/*
 * Packet callback: prints header (if verbose) then injects on the other interface.
 * Combines dummyProcesssPacket() from pcount.c with pcap_inject from psend.c.
 */
void forwardPacket(u_char *arg, const struct pcap_pkthdr *h, const u_char *p) {
  struct bridge_ctx *ctx = (struct bridge_ctx *)arg;
  const u_char *orig_p = p;  /* keep original pointer for pcap_inject */

  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    struct ip6_hdr ip6;

    int s = (h->ts.tv_sec + ctx->thiszone) % 86400;
    printf("%02d:%02d:%02d.%06u [%s->%s] ",
           s / 3600, (s % 3600) / 60, s % 60, (unsigned)h->ts.tv_usec,
           ctx->src_name, ctx->dst_name);

    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);
    printf("[%s -> %s] ",
           etheraddr_string(ehdr.ether_shost, buf1),
           etheraddr_string(ehdr.ether_dhost, buf2));

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p += 4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+sizeof(ehdr), sizeof(struct ip));
      printf("[%s][%s -> %s] ", proto2str(ip.ip_p),
             intoa(ntohl(ip.ip_src.s_addr)), intoa(ntohl(ip.ip_dst.s_addr)));
    } else if(eth_type == 0x86DD) {
      memcpy(&ip6, p+sizeof(ehdr), sizeof(struct ip6_hdr));
      printf("[%s -> %s] ", in6toa(ip6.ip6_src), in6toa(ip6.ip6_dst));
    } else if(eth_type == 0x0806) {
      printf("[ARP] ");
    } else {
      printf("[eth_type=0x%04X] ", eth_type);
    }
    printf("[caplen=%u][len=%u]\n", h->caplen, h->len);

    if(verbose == 2) {
      u_int i;
      for(i = 0; i < h->caplen; i++) printf("%02X ", orig_p[i]);
      printf("\n");
    }
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++;
  numBytes += h->len;

  /* Inject the original packet on the other interface (from psend.c) */
  if(pcap_inject(ctx->dst, orig_p, h->caplen) == -1)
    fprintf(stderr, "pcap_inject error (%s->%s): %s\n",
            ctx->src_name, ctx->dst_name, pcap_geterr(ctx->dst));
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pbridge -i <device> -o <device> [-f <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device>      [Input  interface]\n");
  printf("-o <device>      [Output interface]\n");
  printf("-f <filter>      [BPF filter on -i, e.g. \"not icmp\"]\n");
  printf("-F <filter>      [BPF filter on -o, e.g. \"not icmp\"]\n");
  printf("-l <len>         [Capture length]\n");
  printf("-v <mode>        [Verbose: 1=headers, 2=headers+payload hex]\n");

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;
    printf("\nAvailable devices:\n");
    while(devpointer) {
      const char *descr = devpointer->description;
      if(descr) printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
      else       printf(" %d. %s\n",     i++, devpointer->name);
      devpointer = devpointer->next;
    }
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *dev_in = NULL, *dev_out = NULL, *bpfFilter = NULL, *bpfFilterOut = NULL;
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  int32_t thiszone;
  struct bridge_ctx ctx_in, ctx_out;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc, argv, "hi:o:l:v:f:F:")) != '?') {
    if((c == 255) || (c == (u_char)-1)) break;
    switch(c) {
    case 'h': printHelp(); exit(0);
    case 'i': dev_in       = strdup(optarg); break;
    case 'o': dev_out      = strdup(optarg); break;
    case 'l': snaplen      = atoi(optarg);   break;
    case 'v': verbose      = atoi(optarg);   break;
    case 'f': bpfFilter    = strdup(optarg); break;
    case 'F': bpfFilterOut = strdup(optarg); break;
    }
  }

  if(geteuid() != 0) {
    printf("Please run this tool as superuser\n");
    return(-1);
  }

  if(dev_in == NULL || dev_out == NULL) {
    printf("ERROR: both -i and -o are required\n");
    printHelp();
    return(-1);
  }

  printf("Bridge: %s <-> %s\n", dev_in, dev_out);

  /* Open both interfaces in promiscuous mode */
  if((pd_in = pcap_open_live(dev_in, snaplen, 1, 500, errbuf)) == NULL) {
    printf("pcap_open_live(%s): %s\n", dev_in, errbuf);
    return(-1);
  }
  if((pd_out = pcap_open_live(dev_out, snaplen, 1, 500, errbuf)) == NULL) {
    printf("pcap_open_live(%s): %s\n", dev_out, errbuf);
    return(-1);
  }

  /* Apply BPF filter on -i (input) if specified */
  if(bpfFilter != NULL) {
    if(pcap_compile(pd_in, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error (-f): '%s'\n", pcap_geterr(pd_in));
    } else {
      if(pcap_setfilter(pd_in, &fcode) < 0)
        printf("pcap_setfilter error (-f): '%s'\n", pcap_geterr(pd_in));
    }
  }

  /* Apply BPF filter on -o (output) if specified */
  if(bpfFilterOut != NULL) {
    if(pcap_compile(pd_out, &fcode, bpfFilterOut, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error (-F): '%s'\n", pcap_geterr(pd_out));
    } else {
      if(pcap_setfilter(pd_out, &fcode) < 0)
        printf("pcap_setfilter error (-F): '%s'\n", pcap_geterr(pd_out));
    }
  }

  if(drop_privileges("nobody") < 0)
    return(-1);

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  /* Setup one context per direction */
  ctx_in  = (struct bridge_ctx){ pd_in,  pd_out, dev_in,  dev_out, thiszone };
  ctx_out = (struct bridge_ctx){ pd_out, pd_in,  dev_out, dev_in,  thiszone };

  /* Get selectable file descriptors for both pcap handles */
  int fd_in  = pcap_get_selectable_fd(pd_in);
  int fd_out = pcap_get_selectable_fd(pd_out);
  if(fd_in < 0 || fd_out < 0) {
    fprintf(stderr, "pcap_get_selectable_fd failed\n");
    return(-1);
  }
  int maxfd = (fd_in > fd_out ? fd_in : fd_out) + 1;

  /* Single-threaded bidirectional bridge using select + pcap_next_ex */
  while(keep_running) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd_in,  &readfds);
    FD_SET(fd_out, &readfds);

    int ret = select(maxfd, &readfds, NULL, NULL, NULL);
    if(ret < 0) {
      if(errno == EINTR) continue;   /* interrupted by SIGALRM or SIGINT — recheck keep_running */
      break;
    }

    if(FD_ISSET(fd_in, &readfds)) {
      struct pcap_pkthdr *h;
      const u_char *p;
      int r = pcap_next_ex(pd_in, &h, &p);
      if(r == 1)  forwardPacket((u_char *)&ctx_in, h, p);
    }

    if(FD_ISSET(fd_out, &readfds)) {
      struct pcap_pkthdr *h;
      const u_char *p;
      int r = pcap_next_ex(pd_out, &h, &p);
      if(r == 1)  forwardPacket((u_char *)&ctx_out, h, p);
    }
  }

  print_stats();
  pcap_close(pd_in);
  pcap_close(pd_out);

  return(0);
}
