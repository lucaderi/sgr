/*
  Modifica del codice del programma pcount.c, per aggiungere la funzionalità di bridging, cioè attraverso un nuovo parametro
  (-b <interfaccia>) il programma esegue il bridge tra due interfacce di rete, ovvero inoltrare il traffico entrante 
  dall'interfaccia A verso l'interfaccia B, senza alterarne la forma (l'inoltro avviene per i pacchetti "raw").

  Ogni pacchetto catturato dall'interfaccia sorgente (questo programma), viene preso e inoltrato sulla seconda interfaccia, 
  cioè quella specificata con il parametro (-b).
  es. -> sudo ./pbridge -i <src> -b <dst>
  
  Grazie alle funzionalità da sniffer, si può decidere quale dei pacchetti ricevuti inoltrare.
  es.  -> sudo ./pbridge -i <src> -b <dst> -f "icmp"

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
pcap_t  *pd;                    // pcap handle (cattura pacchetti)
pcap_t  *pd_bridge = NULL;      // pcap handle per interfaccia di bridge (inoltro pacchetti)
int verbose = 0;                // livello di verbosità (0: nessuno, 1: dettagli, 2: dettagli + payload)
struct pcap_stat pcapStats;     // struttura per le statistiche di pcap

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
// Utility di conversione del tempo da GMT a local time (considera anche cambiamenti di giorno e anno)
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

// Formatta un numero con separatori di migliaia e opzionalmente con decimali (utile per statistiche)
char* format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals)	{
  u_int a1 = ((u_long)val / 1000000000) % 1000;	
  u_int a = ((u_long)val / 1000000) % 1000;
  u_int b = ((u_long)val / 1000) % 1000;
  u_int c = (u_long)val % 1000;
  u_int d = (u_int)((val - (u_long)val)*100) % 100;

  // Aggiunta decimali (per valori più piccoli) 
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
// Funzione per droppare i privilegi (es. da root a nobody) dopo aver aperto l'interfaccia di cattura
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
long delta_time (struct timeval * now, struct timeval * before) {
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
// Funzione di stampa per le statistiche di cattura (numero di pacchetti, velocità, ecc.)
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
// Funzione di gestione dei segnali per terminare il programma in modo pulito (stampa statistiche e chiude pcap)
void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  pcap_breakloop(pd);
}

/* ******************************** */
// Funzione di gestione del segnale di allarme per stampare periodicamente le statistiche durante la cattura
void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */
// Funzione per convertire un indirizzo MAC in stringa leggibile (es. "00:11:22:33:44:55")
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

// Funzione per convertire un indirizzo IPv4 in stringa leggibile (rimpiazza inet_ntoa() con una versione più veloce)
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
// Funzione per convertire un indirizzo IPv6 in stringa leggibile
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
// Funzione per convertire un numero di protocollo IP in stringa leggibile (es. 6 -> "TCP", 17 -> "UDP")
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

static int32_t thiszone;      // variabile per conversione da GMT a local time

// Callback per processare ogni pacchetto catturato (stampa dettagli e opzionalmente payload, aggiorna statistiche)
void dummyProcesssPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {

  // Se è stato specificato un file di dump, salva il pacchetto catturato su quel file
  if(dumper) 
    pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)h, p);
  
  // Se è attiva la verbosità, stampa i dettagli del pacchetto (timestamp, indirizzi MAC, IP, protocollo, ecc.)
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

  // Se numero di pacchetti è 0, inizializza il timer di inizio cattura, poi aggiorna contatore di pacchetti e di byte catturati
  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++, numBytes += h->len;

  // Se attiva verbosità 2, stampa anche il payload del pacchetto in formato esadecimale
  if(verbose == 2) {
      int i;

      for(i = 0; i < h->caplen; i++)
        printf("%02X ", p[i]);
      printf("\n");
  }

  // Se è stata specificata un'interfaccia di bridge, inoltra il pacchetto catturato su quella interfaccia
  if(pd_bridge) {
    int res = pcap_sendpacket(pd_bridge, p, h->caplen);
    if(res != 0) {
      fprintf(stderr, "Error sending packet on bridge interface: %s\n", pcap_geterr(pd_bridge));
    }
  }

 }

/* *************************************** */
// Funzione di stampa per le istruzioni d'uso del programma e elenco delle interfacce disponibili
void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
  printf("-h               [Print help]\n");
  printf("-i <device|path> [Device name or file path]\n");
  printf("-b <device>       [Target device for bridging/forwarding]\n");      // interfaccia destinazine bridging
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
// Main: gestisce i parametri, apre l'interfaccia di cattura, imposta il filtro BPF, droppa i privilegi, avvia il loop di cattura 

int main(int argc, char* argv[]) {

  // Variabili per gestione parametri, errori, configurazione pcap e statistiche
  char *device = NULL, *bpfFilter = NULL, *bridge_device = NULL;
  u_char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  struct stat s;
  
  // Conversione GMT -> local time
  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  // Fino a quando ci sono parametri da processare, gestisce ogni opzione
  while((c = getopt(argc, argv, "hi:b:l:v:f:w:")) != '?') {
    if((c == 255) || (c == (u_char)-1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;

    case 'i':
      device = strdup(optarg);
      break;
  
    case 'b':
      bridge_device = strdup(optarg);
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
    }
    
  }
  
  // Verifica se l'utente è root (necessario per catturare pacchetti), altrimenti esce con messaggio di errore
  if(geteuid() != 0) {
    printf("Please run this tool as superuser\n");
    return(-1);
  }
  
  // Verifica se è stata specificata un'interfaccia di cattura, altrimenti esce con messaggio di errore
  if(device == NULL) {
    printf("ERROR: Missing -i\n");    
    printHelp();
    return(-1);  
  }

  printf("Capturing from %s\n", device);

  // Verifica se il parametro -i è un file (pcap offline) o un'interfaccia di rete (pcap live) e apre di conseguenza
  if(stat(device, &s) == 0) {
    /* Device is a file on filesystem */
    if((pd = pcap_open_offline(device, errbuf)) == NULL) {
      printf("pcap_open_offline: %s\n", errbuf);
      return(-1);
    }
  } else {  
    // Il dispositivo è un'interfaccia di rete
    promisc = 1;    // modalità promiscua per catturare tutto il traffico

    // Verifica se c'è specificata interfaccia di bridge da aprire per l'inoltro dei pacchetti
    if(bridge_device) {
      printf("Bridging to %s\n", bridge_device);
      if((pd_bridge = pcap_open_live(bridge_device, snaplen, promisc, 500, errbuf)) == NULL) {
        printf("pcap_open_live for bridge device: %s\n", errbuf);
        return(-1);
      }
    }
    
    // Nessuna interfaccia di bridge specificata, si limita a catturare i pacchetti senza inoltrarli
    if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {    /* hardcode: promisc=1, to_ms=500 */
      printf("pcap_open_live: %s\n", errbuf);
      return(-1);
    }
  }

  // Se è stato specificato un filtro BPF, lo compila e lo applica alla cattura
  if(bpfFilter != NULL) {
    if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode) < 0) {
        printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
    }
  }

  // Dopo aver aperto l'interfaccia di cattura, droppa i privilegi (es. da root a nobody) per sicurezza
  if(drop_privileges("nobody") < 0)
    return(-1);
  
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  // Se non è attiva la modalità verbose, imposta un timer per stampare periodicamente le statistiche durante la cattura
  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  /*-------- Loop --------*/
  // Avvia il loop di cattura, che chiama la funzione dummyProcesssPacket per ogni pacchetto catturato
  pcap_loop(pd, -1, dummyProcesssPacket, NULL);

  // Quando il loop termina (es. per segnale), stampa le statistiche finali, chiude pcap e il file di dump se aperto
  print_stats();

  /*------ Arresto ------*/
  // Chiude l'interfaccia di cattura
  pcap_close(pd);

  if(pd_bridge)          
    pcap_close(pd_bridge);    // Se è stato aperto un handle per l'interfaccia di bridge, lo chiude

  // Se è stato aperto un file di dump, lo chiude
  if(dumper)
    pcap_dump_close(dumper);
  
  return(0);
}