/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pcount.c -o pcount -lpcap
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
pcap_t  *pd1;
pcap_t  *pd2;
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
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

#include <pthread.h> // mi server per poter eseguire contemporaneamente i due pcap_loop sullo stesso processo

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;

void send_packet(pcap_t *handle, const unsigned char *packet, int len);

// mi serve per poter smettere di ciclare, liberare le risorse e chiudere il programma
volatile sig_atomic_t stop = 0;

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

// funzione invocata per ridurre i privilegi del processo dopo che ha fatto le
// operazioni che richiedono privilegi elevati
int drop_privileges(const char *username) {
  struct passwd *pw = NULL;

  // controllo se sono root
  // getuid() --> ritorna id dell'utente dle processo
  // getgid() --> ritorna id del gruppo
  // se entrambi != 0 significa che non sono root
  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return -1; // funzione termina perche non ci sono provilegi da rilasciare
  }

  // cerca username nella lista utenti --> restituisce struct
  // passwd con info tipo UID e GID
  pw = getpwnam(username);

  // se l'utente non esiste, utilizza l'utente di sistema "nobody"
  // che ha privilegi minimi
  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  // cambia utente e gruppo --> usa dei setters
  // dopo questa chiamata l'utente non è piu root ma agisce con i
  // permessi dell'utente piu limitato
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

  // fa si che i file creati dall'utente nobody
  // abbiano permessi standard completi ???
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

  if(pcap_stats(pd1, &pcapStat) >= 0) {
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
  fprintf(stderr, "Leaving...\n");
  stop = 1;
}

/* ******************************** */

// HANDLER
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

/*
 * Callback chiamata da pcap_loop per ogni pacchetto catturato
 * Qua mi limito solamente a stampare delle informazioni relative a esso, ma è qua che posso
 * fare eventualmente analisi (processing)
 */
void dummyProcessPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h, // header del pacchetto
			 const u_char *p) { // puntatore al payload (ai byte) del pacchetto
  // serve per le statistiche
  numPkts++;
  numBytes += h->caplen;

  pcap_t *dst = (pcap_t*)_deviceId;
  send_packet(dst, p, h->caplen); // --> usa pcap_inject per inviare il pacchetto raw sulla rete (vedi sotto...)
}

void send_packet(pcap_t *handle, const unsigned char *packet, int len) {
  if (pcap_inject(handle, packet, len) == -1) {
    // serve per inviare pacchetti "raw" sulla rete tramite l'handle aperto
    // - handle --> indica su quale interfaccia inviare il pacchetto
    // - packet --> puntatore ai dati del pacchetto da inviare (es: ARP, ICMP, ...)
    // - len --> lunghezza del pacchetto in byte
    fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
    exit(1);
  }
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-o <device2|path> [Device2 name or file path]\n");
  printf("-f <filter>      [pcap filter]\n");
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
  char *device = NULL, *device2 = NULL, *bpfFilter = NULL;
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode; // struttura usata da libcap per rappresentare un filtro BPF compilato (il bytecode)
  struct stat s; // struttura che memorizza informazioni riguardanti file/risorsa nel file system

  startTime.tv_sec = 0; // inizializzo il tempo di
  thiszone = gmt_to_local(0);

  //ES. ./pcount -i eth0 -v 1 -f "tcp"
  while((c = getopt(argc, argv, "hi:o:l:v:f:w:")) != '?') { // analizza le opzioni passate al programma per linea di comando
    if((c == 255) || (c == (u_char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    case 'i':
      device = strdup(optarg); // salva il nome dell'interfaccia di rete
      break;

    case 'o':
      device2 = strdup(optarg); // salva il nome della seconda interfaccia di rete
      break;

    case 'l':
      snaplen = atoi(optarg); // numero massimo di byte da catturare per pacchetto
      break;

    case 'v':
      verbose = atoi(optarg); // livello di dettaglio output --> 1: info base, 2: anche payload
      break;

    case 'w':
      dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg); // salva i pacchetti in un file .pcap
      if(dumper == NULL) {
        printf("Unable to open dump file %s\n", optarg);
        return(-1);
      }
      break;

    case 'f':
      bpfFilter = strdup(optarg); // filtro BPF --> es: "tcp", "port 80"
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

  if(device2 == NULL) {
    printf("ERROR: Missing -o\n");
    printHelp();
    return(-1);
  }

  printf("Capturing from %s\n", device);

  if(stat(device, &s) == 0) { // stat() verifica se device esiste come file nel filesystem --> 0 == esiste; se non esiste lo trattiamo come nome di interfaccia (es: eth0)
    /* Device is a file (probabilmente .pcap) on filesystem */
    if((pd1 = pcap_open_offline(device, errbuf)) == NULL) { // non stiamo catturando traffico live --> leggiamo pacchetti gia salvati (file .pcap)
      // Es: ./pcount -i traffico.pcap
      // restituisce un hanlder(pd) per leggere i pacchetti
      printf("pcap_open_offline: %s\n", errbuf);
      return(-1);
    }
  } else {
    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1; // mi server per poter vedere tutti i pacchetti che transitano --> la scheda di rete fa filtraggio ad hw, scarterebbe pacchetti non diretti al mio MAC Address
    if((pd1 = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) { // in questo caso invece facciamo sniffing live
      // timeout di 500 ms server per evitare che il programma resti bloccato se non arrivano pacchetti per molto tempo
      // --> per programmi che gestiscono anche l'interfaccia grafica

      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
    // serve per settarlo a non bloccnate di modo tale che riesca a lavorare
    // in modo event-driven e non usare i thread
    // OSS: questo in realta, che ho aggiunto per fine didattico, nel mio contesto è opzionale
    // perche tanto gestisco gia con la poll, anzi forse meglio dato che evito il busy waiting che avrei altrimenti
    // facendo un semplice ciclo while(1) con solo dispatch
    pcap_setnonblock(pd1, 1, errbuf);
  }

  if(stat(device2, &s) == 0) { // stat() verifica se device esiste come file nel filesystem --> 0 == esiste; se non esiste lo trattiamo come nome di interfaccia (es: eth0)
    /* Device is a file (probabilmente .pcap) on filesystem */
    if((pd2 = pcap_open_offline(device2, errbuf)) == NULL) { // non stiamo catturando traffico live --> leggiamo pacchetti gia salvati (file .pcap)
      // Es: ./pcount -i traffico.pcap
      // restituisce un hanlder(pd) per leggere i pacchetti
      printf("pcap_open_offline: %s\n", errbuf);
      return(-1);
    }
  } else {
    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1; // mi server per poter vedere tutti i pacchetti che transitano --> la scheda di rete fa filtraggio ad hw, scarterebbe pacchetti non diretti al mio MAC Address
    if((pd2 = pcap_open_live(device2, snaplen, promisc, 500, errbuf)) == NULL) { // in questo caso invece facciamo sniffing live
      // timeout di 500 ms server per evitare che il programma resti bloccato se non arrivano pacchetti per molto tempo
      // --> per programmi che gestiscono anche l'interfaccia grafica

      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
    // serve per settarlo a non bloccnate di modo tale che riesca a lavorare
    // in modo event-driven e non usare i thread
    // OSS: questo in realta, che ho aggiunto per fine didattico, nel mio contesto è opzionale
    // perche tanto gestisco gia con la poll, anzi forse meglio dato che evito il busy waiting che avrei altrimenti
    // facendo un semplice ciclo while(1) con solo dispatch
    pcap_setnonblock(pd2, 1, errbuf);
  }

  if(bpfFilter != NULL) {
    if(pcap_compile(pd1, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) { // da "tcp port 80" a bytecode BPF eseguibile nel kernel
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd1));
    } else {
      if(pcap_setfilter(pd1, &fcode) < 0) { // --> dopo questo arrivano solo pacchetti che matchano col filtro
	      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd1));
      }
    }
  }

  /*
   * IMPORTANTISSIMO PER LA SICUREZZA
   *
   * Per catturare i pacchetti serve essere root, ma restare root è pericoloso!
   * QUELLO CHE SI FA:
   * - apro la cattura (come root)
   * - poi divento utente "nobody" --> super limitato
   *
   * In questo modo anche se il programma crasha, un attaccante non ha
   * privilegi di root a partire da questo programma
   */
  if(drop_privileges("nobody") < 0)
    return(-1);

  // facciamo in modod di permttere di intercettare ^C e di chiudere
  // quindi il programma in modo pulito
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) { // ogni secondo stampa statistiche (pacchetti, throughput, ...)
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  printf("Bridge in funzione: %s <-> %s\n", device, device2);

  /*
   * LOOP PRINCIPALE --> sniffing vero e proprio
   *
   * Ho dovuto tirare su due thread per riuscire a strutturare il parallelismo
   * di comunicazione tra le due interfacce. Senza il primo pcap_loop avrebbe
   * bloccato l'esecuzione del secondo finche carico di disponibilita di pacchetti da inviare
   * In questo modo il bridge funziona correttamente
   */
  // ottengo i file descriptor
  // OSS: pd1 e pd2 non sono file descriptor ma puntatori a una struttura pcap_t
  // che contiene info come buffer, stato interno, config BPF, ecc... --> non è quindi utilizzabile con poll/select()
  int fd1 = pcap_get_selectable_fd(pd1);
  int fd2 = pcap_get_selectable_fd(pd2);

  if (fd1 < 0 || fd2 < 0) {
    fprintf(stderr, "fd not available\n");
  }

  // questa struttura serve alla poll() per sapere cosa su cosa deve aspettare
  // e cosa deve monitorare (aspetta su fd1 e fd2 e svegliati quando ci sono pacchetti da leggere (POLLIN))
  struct pollfd fds[2];

  fds[0].fd = fd1;
  fds[0].events = POLLIN;

  fds[1].fd = fd2;
  fds[1].events = POLLIN;

  while(!stop) { // fin tanto che non è arrivato SIGINT
    // il kernel si mette in attesa controllando entrambe le interfacce
    // si sblocca quando per almeno una delle due ci sono dei dati
    int ret = poll(fds, 2, -1);
    // fds --> struct polldfd, ci dice quale fd monitorare
    // 2 --> numero di interfacce (fd) da monitorare (in questo caso 2 per l'appunto)
    // -1 --> attesa infinita

    if(ret < 0) {
      if(errno == EINTR) continue; // interrotto da segnale
    }

    if(fds[0].revents & POLLIN) {
      pcap_dispatch(pd1, 1, dummyProcessPacket, (u_char*)pd2);
    }
    if(fds[1].revents & POLLIN) {
      pcap_dispatch(pd2, 1, dummyProcessPacket, (u_char*)pd1);
    }
  }

  print_stats();

  pcap_close(pd1);
  pcap_close(pd2);

  if(dumper)
    pcap_dump_close(dumper);

  return(0);
}
