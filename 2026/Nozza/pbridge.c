/*
Modifiche rispetto a pcount.c:
- parametro -o
- riferimento al device di output pd_out
- apertura di tale device 
- iniezione dei pacchetti al'interno della funzione 'dummyProcessPacket'
*/

/* Comportamento del programma come 
 * pcount.c in assenza di -o <interface> */

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

/* Aggiunto puntatore a descrittore di sessione 
 * per gestire la sessione di acquisizione live 
 * di device_out */
pcap_t  *pd_out; 

int verbose = 0;
struct pcap_stat pcapStats;
  
/* Aggiunta logica per interrompere bridging */
volatile sig_atomic_t running_flag = 1;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;

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
long delta_time (struct timeval * now,
                 struct timeval * before) {
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

  running_flag = 0;
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

void dummyProcessPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {       

  if(dumper)
    pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)h, p);
  
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    struct ip6_hdr ip6;

    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);
    printf("[%s -> %s] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2));

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+sizeof(ehdr), sizeof(struct ip));
      printf("[%s]", proto2str(ip.ip_p));
      printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
      printf("-> %s] ", intoa(ntohl(ip.ip_dst.s_addr)));
    } else if(eth_type == 0x86DD) {
      memcpy(&ip6, p+sizeof(ehdr), sizeof(struct ip6_hdr));
      printf("[%s ", in6toa(ip6.ip6_src));
      printf("-> %s] ", in6toa(ip6.ip6_dst));
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);

    printf("[caplen=%u][len=%u]\n", h->caplen, h->len);
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++, numBytes += h->len;

  if(verbose == 2) {
      int i;

      for(i = 0; i < h->caplen; i++)
        printf("%02X ", p[i]);
      printf("\n");
  }
 }

/* *************************************** */

void printHelp(void) { /* Aggiunta stampa helper -o */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-o <interface>][-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-f <filter>      [pcap filter]\n");
  printf("-w <path>        [pcap write file]\n");  
  printf("-l <len>         [Capture length]\n");
  printf("-o <interface>   [Adds interface to bridge]\n");
  printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");

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

int main(int argc, char* argv[]) {
  char *device = NULL, *bpfFilter = NULL;
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  struct stat s;

  /* Aggiunta nome dispositivo di uscita */
  char *device_out = NULL;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);
  
  /* Aggiormento parsing */
  while((c = getopt(argc, argv, "hi:l:v:f:w:o:")) != '?') {
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
    
    case 'o':
      device_out = strdup(optarg);
      break;

    case 'f':
      bpfFilter = strdup(optarg);
      break;
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

  /* Apertura sessione live di trasmissione */
  if(device_out) {
    printf("Bridging with %s\n", device_out);    
    promisc = 1;
    if ((pd_out = pcap_open_live(device_out, snaplen, promisc, 500, errbuf)) == NULL) {
      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
  }

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

  if(bpfFilter != NULL) {
    if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
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

  /* Comportamento pcount.c */
  if(device_out == NULL) {
    pcap_loop(pd, -1, dummyProcessPacket, NULL);
  } else {
    int pd_fd = pcap_get_selectable_fd(pd);
    int pd_out_fd = pcap_get_selectable_fd(pd_out);
    
    struct pollfd fds[2];
    fds[0].fd = pd_fd;
    fds[0].events = POLLIN;
    fds[1].fd = pd_out_fd;
    fds[1].events = POLLIN;
  
    struct pcap_pkthdr *header;
    const u_char *packet_data;
    
    /* Bridge bidirezionale */
    while (running_flag) {
      int poll_retval = poll(fds, 2, 1000);
      
      if(poll_retval <= 0) continue;
      
      if(fds[0].revents & POLLIN) {
        if(pcap_next_ex(pd, &header, &packet_data) == 1) {
          pcap_sendpacket(pd_out, packet_data, header->caplen);
          dummyProcessPacket(NULL, header, packet_data);
        }
      }

      if(fds[1].revents & POLLIN) {
        if(pcap_next_ex(pd_out, &header, &packet_data) == 1) {
          pcap_sendpacket(pd, packet_data, header->caplen);
          dummyProcessPacket(NULL, header, packet_data);
        }
      }
    }
  }

  print_stats();

  pcap_close(pd);

  if(dumper)
    pcap_dump_close(dumper);
  
  return(0);
}
