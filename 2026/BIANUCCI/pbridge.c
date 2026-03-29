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

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
static unsigned long long failedPkts = 0;
pcap_dumper_t *dumper = NULL;

void send_packet(pcap_t *handle, const unsigned char *packet, int len);

// mi serve per poter smettere di ciclare, liberare le risorse e chiudere il programma
volatile sig_atomic_t stop = 0;

/* *************************************** */

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
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec] - %llu failed\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000),
	    failedPkts);

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

/*
 * Callback chiamata da pcap_loop per ogni pacchetto catturato
 * Qua mi limito solamente ad aggiornare delle informazioni per le statistiche, ma è qua che posso
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
    failedPkts++;
    return;
  }
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("Usage: pcount [-h] -i <device> -o <device2> [-l <len>] \n");
  printf("-h               [Print help]\n");
  printf("-i <device>      [Device name]\n");
  printf("-o <device2>     [Device2 name]\n");
  printf("-l <len>         [Capture length]\n");

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

// funzione che gestisce l'apertura in modalita live di un'interfaccia di rete
pcap_t* open_live_interface(const char *device, int promisc, int snaplen) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pd;

  if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
    // timeout di 500 ms server per evitare che il programma resti bloccato se non arrivano pacchetti per molto tempo
    // --> per programmi che gestiscono anche l'interfaccia grafica
    printf("pcap_open_live: %s\n", errbuf);
    return NULL;
  }

  // serve per settarlo a non bloccnate di modo tale che riesca a lavorare
  // in modo event-driven e non usare i thread
  // OSS: questo in realta, che ho aggiunto per fine didattico, nel mio contesto è opzionale
  // perche tanto gestisco gia con la poll, anzi forse meglio dato che evito il busy waiting che avrei altrimenti
  // facendo un semplice ciclo while(1) con solo dispatch
  pcap_setnonblock(pd, 1, errbuf);

  // funzione di libpcap che consente di impostare la direzione dei
  // pacchetti che la libreria libpcap catturerà sull’interfaccia di rete pd
  // --> in questo modo evito il rischio di catturare accidentalmente
  // i pacchetti che io stesso (interfaccia 1/2) ho inviato all'altra
  // riducendo quindi il richio di loop e traffico duplicato
  pcap_setdirection(pd, PCAP_D_IN);

  return pd;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *device2 = NULL;
  u_char c;
  int promisc, snaplen = DEFAULT_SNAPLEN;

  startTime.tv_sec = 0; // inizializzo il tempo di

  //ES. ./pcount -i eth0 -v 1 -f "tcp"
  while((c = getopt(argc, argv, "hi:o:l:")) != '?') {
    // analizza le opzioni passate al programma per linea di comando
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

  // apro le interfacce di rete
  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1; // mi server per poter vedere tutti i pacchetti che transitano --> la scheda di rete fa filtraggio ad hw, scarterebbe pacchetti non diretti al mio MAC Address
  if((pd1 = open_live_interface(device, promisc, snaplen)) == NULL) // in questo caso invece facciamo sniffing live
    return(-1);
  if((pd2 = open_live_interface(device2, promisc, snaplen)) == NULL)
    return(-1);

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

  // ogni secondo stampa statistiche (pacchetti, throughput, ...)
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  printf("Bridge in funzione: %s <-> %s\n", device, device2);

  /*
   * LOOP PRINCIPALE --> sniffing vero e proprio
   */
  // ottengo i file descriptor
  // OSS: pd1 e pd2 non sono file descriptor ma puntatori a una struttura pcap_t
  // che contiene info come buffer, stato interno, config BPF, ecc... --> non è quindi utilizzabile con poll/select()
  int fd1 = pcap_get_selectable_fd(pd1);
  int fd2 = pcap_get_selectable_fd(pd2);

  if (fd1 < 0 || fd2 < 0) {
    fprintf(stderr, "fd not available\n");
    return -1;
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

    if(ret < 0) { // interrotto da segnale
      if(errno == EINTR) continue;
      perror("poll");
      break;
    }

    if(fds[0].revents & POLLIN) {
      // pcap_dispatch(..., 1, ...) processa un pacchetto alla volta
      // pcap_dispatch(..., -1, ...) prende tutto il buffer (+ efficiente, lavora a blocchi)
      if(pcap_dispatch(pd1, -1, dummyProcessPacket, (u_char*)pd2) < 0)
        fprintf(stderr, "pcap_dispatch pd1 -> pd2 error\n");
    }
    if(fds[1].revents & POLLIN) {
      if(pcap_dispatch(pd2, -1, dummyProcessPacket, (u_char*)pd1) < 0)
        fprintf(stderr, "pcap_dispatch pd2 -> pd1 error\n");
    }
  }

  print_stats();

  pcap_close(pd1);
  pcap_close(pd2);

  return(0);
}
