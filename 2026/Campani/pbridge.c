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
pcap_t *pd_out; // Descrittore invio 
int verbose = 0;
struct pcap_stat pcapStats;
volatile int running = 1; 

#include <sys/types.h>
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
  running = 0;
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

void fromAtoB(u_char *arg, const struct pcap_pkthdr *h, const  u_char *p){
  if(pcap_inject(pd_out, p, h->caplen) == -1){
    fprintf(stderr, "pcap_inject failed %s\n", pcap_geterr(pd_out));
    return;
  }

  if(dumper) pcap_dump((u_char *)dumper, h, p);

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++; 
  numBytes += h->len; 
}

void fromBtoA(u_char *arg, const struct pcap_pkthdr *h, const  u_char *p){
  if(pcap_inject(pd, p, h->caplen) == -1){
    fprintf(stderr, "pcap_inject failed %s\n", pcap_geterr(pd));
    return; 
  }

  if(dumper) pcap_dump((u_char *)dumper, h, p);

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++; 
  numBytes += h->len; 
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device> -o <device> [-w <path>] [-I <filter>] [-O <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device>      [Input device name]\n");
  printf("-o <device>      [Output device name]\n");
  printf("-I <filter>      [pcap filter on -i]\n");
  printf("-O <filter>      [pcap filter on -o]\n");
  printf("-w <path>        [pcap write file]\n");  
  printf("-l <len>         [Capture length]\n");
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
  char *device_in = NULL, *device_out = NULL, *bpfFilter_in = NULL, *bpfFilter_out = NULL;
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode_in, fcode_out;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc, argv, "hi:o:l:v:w:I:O:")) != '?') {
    if((c == 255) || (c == (u_char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    case 'i':
      device_in = strdup(optarg);
      break;
    
    case 'o':
      device_out = strdup(optarg);
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

    case 'I':
      bpfFilter_in = strdup(optarg);
      break;

    case 'O':
      bpfFilter_out = strdup(optarg);
      break; 
    }
  }
  
  if(geteuid() != 0) {
    printf("Please run this tool as superuser\n");
    return(-1);
  }
  
  if(device_in == NULL) {
    printf("ERROR: Missing -i\n");    
    printHelp();
    return(-1);  
  }

  if(device_out == NULL){
    printf("ERROR: Missing -o\n");
    printHelp(); 
    return(-1);
  }


  // Apertura interfaccia di input
  if(device_in != NULL){
    pd = pcap_open_live(device_in, snaplen, 1, 1000, errbuf);
    if(pd == NULL){
      printf("pcap_open_live (input): %s\n", errbuf); 
      return(-1);
    }
    printf("Input interface %s opened successfully.\n", device_in);
  }

  // Apertura interfaccia di Output
  if(device_out != NULL){
    pd_out = pcap_open_live(device_out, snaplen, 1, 1000, errbuf);
    if(pd_out == NULL){
        printf("pcap_open_live (output): %s\n", errbuf);
        return(-1); 
    }
    printf("Output interface %s opened successfully.\n", device_out);
  }

  // bpfFilter input
  if(bpfFilter_in != NULL) {
    if(pcap_compile(pd, &fcode_in, bpfFilter_in, 1, 0xFFFFFF00) < 0) {
      printf("Input pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode_in) < 0) {
	      printf("Input pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
    }
  }

  //bpfFilter output
  if(bpfFilter_out != NULL){
    if(pcap_compile(pd_out, &fcode_out, bpfFilter_out, 1, 0xFFFFFF00) < 0){
      printf("Output pcap_compile error: '%s'\n", pcap_geterr(pd_out)); 
    }
    else{
      if(pcap_setfilter(pd_out, &fcode_out) < 0){
        printf("Output pcap_setfilter error: '%s'\n", pcap_geterr(pd_out));
      }
    }
  }

  if(pcap_setdirection(pd, PCAP_D_IN) == -1){
    fprintf(stderr, "input setdirection failed %s\n", pcap_geterr(pd));
    return(-1);
  }
  if(pcap_setdirection(pd_out, PCAP_D_IN) == -1){
    fprintf(stderr, "output setdirection failed %s\n", pcap_geterr(pd_out)); 
    return(-1);
  }

  //Modalità non bloccante
  if(pcap_setnonblock(pd, 1, errbuf) == -1){
    fprintf(stderr, "input setnonblock error %s\n", errbuf);
  }
  if(pcap_setnonblock(pd_out, 1, errbuf) == -1){
    fprintf(stderr, "output setnonblock error %s\n", errbuf); 
  } 

  if(drop_privileges("nobody") < 0)
    return(-1);
  
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  int fd_in = pcap_get_selectable_fd(pd);
  int fd_out = pcap_get_selectable_fd(pd_out); 
  if(fd_in < 0 || fd_out < 0){
    fprintf(stderr, "pcap_get_selectable_fd failed\n");
    return -1; 
  }

  int max_fd = (fd_in > fd_out ? fd_in : fd_out) + 1;

  while(running){
    fd_set readfds; 
    FD_ZERO(&readfds);
    FD_SET(fd_in, &readfds);
    FD_SET(fd_out, &readfds);

    int ret = select(max_fd, &readfds, NULL, NULL, NULL);
    if(ret < 0){
      if(errno == EINTR) continue; 

      fprintf(stderr, "select() failed errno(=%d): %s\n", errno, strerror(errno)); 
      break; 
    }

    if(FD_ISSET(fd_in, &readfds)){
      pcap_dispatch(pd, -1, fromAtoB, (u_char*)pd_out);
    }

    if(FD_ISSET(fd_out, &readfds)){
      pcap_dispatch(pd_out, -1, fromBtoA, (u_char*)pd);
    }
  }

  print_stats();

  pcap_close(pd);
  pcap_close(pd_out); 

  if(dumper)
    pcap_dump_close(dumper);
  
  return(0);
}
