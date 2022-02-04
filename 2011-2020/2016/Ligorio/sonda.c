/*
 * sonda.c
 * 
 * Progetto gestione di reti 2015/2016
 *
 * Realizzato da Francesco Ligorio  
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <string.h>

#include "support.h"

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <errno.h>

#include <unistd.h>
#include <signal.h>
#include <time.h>

#define DEFAULT_SNAPLEN 500
#define DEFAULT_TIMEOUT 0
#define DEFAULT_PROMISC 1
#define EXECUTION_TIME 1        /* Tempo di esecuzione sul generico canale */
#define DATALINK_TYPE 127       /* Intestazione del livello link nota  */
#define CLEAN_TIMEOUT 20        /* Timeout per il controllo della consistenza della struttura */


#define IFERRORM1(x) if(x == -1){		\
    printf("%s\n", strerror(errno));		\
    exit(EXIT_FAILURE);				\
  }

#define IFERRORNULL(x, y) if(x == NULL){		\
    printf("%s\n", y);					\
    exit(EXIT_FAILURE);					\
  }


typedef struct _radiotap_hdr {
  uint16_t hdr_rev_pad,         /* Header revision + Header pad */  
    header_length;              /* Header length */
  uint32_t pf;                  /* Present flags */
  uint64_t tsmp;                /* Timestamp */
  uint16_t fr,                  /* Flags + Data Rate */
    channel,                    /* Channel frequency */
    channelf;                   /* Channel flags */
  int8_t signal;                /* Signal */
} radiotap_hdr;

typedef struct _beacon_info {
  uint16_t frameControl;        /* Frame Control */
  uint16_t duration;            /* Duration */  
  u_char dest_address[6],       /* Destination address */
    source_address[6],          /* Source address */
    bssid[6];                   /* Bssid */
  uint16_t fn;                  /* Fragment Number */
  uint64_t tsmp;                /* Timestamp */
  uint16_t bi,                  /* Beacon Interval */
    cap_info;                   /* Capabilities information */
  uint8_t tag_num,              /* Tag number */
    tag_length;                 /* Tag length */
  char essid[33];               /* Essid */
} beacon_info;

typedef struct _data_info{
  uint16_t frameControl,        /* Frame Control */
    duration;                   /* Duration */
  u_char bssid[6],              /* Bssid */
    station[6];                 /* Station  */
} data_info;


/* <Variabili globali> */
ap_list access_points;
pcap_t *handle = NULL;
int sockfd;

const __s32 frequencies[13] = {
  2412,                         /* Channel 01 */
  2417,                         /* Channel 02 */
  2422,                         /* Channel 03 */
  2427,                         /* Channel 04 */
  2432,                         /* Channel 05 */
  2437,                         /* Channel 06 */
  2442,                         /* Channel 07 */
  2447,                         /* Channel 08 */
  2452,                         /* Channel 09 */
  2457,                         /* Channel 10 */
  2462,                         /* Channel 11 */
  2467,                         /* Channel 12 */
  2472                          /* Channel 13 */
};
/* </Variabili globali> */

/* Procedura che analizza il pacchetto catturato mediante opportuni filtri
 * e che dunque aggiorna la struttura utilizzata per mantenere l'informazione.
 */
void _worker(const struct pcap_pkthdr *h, const u_char *bytes, int verbose){

  radiotap_hdr *rd_hdr = (radiotap_hdr *) bytes;
  beacon_info *bcn = (beacon_info *) (bytes + rd_hdr->header_length);
  data_info *data = (data_info *) (bytes + rd_hdr->header_length);

  /* Rappresentazione del campo Frame Control in Host Bytes Order
   * e recupero dei campi interessanti ai fini dell'impostazione
   * del filtro di cattura
   */
  
  uint16_t fcns = ntohs(bcn->frameControl);
  uint16_t fc_type = (fcns>>10)&3;
  uint16_t fc_subtype = (fcns>>12)&15;
  uint16_t fc_dsStatus = fcns&3;
  
  /* Filtri di cattura  */
  if (fc_type == 0 && fc_subtype == 8){
    bcn->essid[bcn->tag_length] = '\0';
    update_ap(&access_points, bcn->essid, bcn->bssid, rd_hdr->channel, rd_hdr->signal, *h);
    if (verbose)
      print_beacon(*h, bcn->essid, bcn->bssid, rd_hdr->channel, rd_hdr->signal);
  }
  else if (fc_type == 2 && fc_dsStatus == 1){ 
    update_stations(&access_points, data->bssid, data->station, rd_hdr->channel, *h);
    if (verbose)
      print_data(*h, data->bssid, data->station, rd_hdr->channel, rd_hdr->signal);
  }
}


void _callback(pcap_t * handle, int max_time, int verbose){

  fd_set set;
  struct timeval timeout,
    begin,
    end;
  int fd,
    execution_time = EXECUTION_TIME,
    done = 0,
    sel;
  const u_char *bytes;
  struct pcap_pkthdr pkthdr;
  double diff;
  
  if ((fd = pcap_get_selectable_fd(handle)) == -1){
    printf("sonda: errore recupero file descriptor per la cattura\n");
    exit(EXIT_FAILURE);
  }
  
  timeout.tv_sec = max_time;
  timeout.tv_usec = 0;
  
  FD_CLR(fd, &set);
  FD_SET(fd, &set);

  IFERRORM1(gettimeofday(&begin, NULL));

  /* Implementazione del timeout di cattura per consentire il cambio di frequenza */
  while(!done){
    IFERRORM1((sel = select(fd + 1, &set, NULL, NULL, &timeout)));
    if ((bytes = pcap_next(handle, &pkthdr)) == NULL){
      printf("sonda: errore lettura pacchetti\n");
      exit(EXIT_FAILURE);
    }
    /* Pacchetto catturato, eseguo procedura "worker" per analizzarlo */
    if (sel != 0)
      _worker(&pkthdr, bytes, verbose);

    IFERRORM1(gettimeofday(&end, NULL));
    diff = difftime(end.tv_sec, begin.tv_sec);
    if (diff >= execution_time)
      done++;
  }
  
}

/* Stampa risultato della cattura in formato JSON, libera la 
 * memoria e chiude i descrittori rimasti aperti.
 */
static void sigint_handler(int signum){

  make_json(access_points);
  free_aps(&access_points);
  IFERRORM1(close(sockfd));
  pcap_close(handle);
  _exit(EXIT_SUCCESS);

}
    
int main(int argc, char **argv){

  char errbuf[PCAP_ERRBUF_SIZE],
    *device = NULL,
    *optstring = "i:v",
    opt;
  const char *datalink_descr = NULL;
  int snaplen = DEFAULT_SNAPLEN,
    timeout = DEFAULT_TIMEOUT,
    promisc = DEFAULT_PROMISC,
    execution_time = EXECUTION_TIME,
    index = 0,
    datalink_type,
    verbose = 0;
  double clean_timeout = CLEAN_TIMEOUT;
  struct iwreq iwr;
  struct sigaction sa;  
  
  access_points = new_ap_list();
  
  
  /* Registrazione gestore segnale SIGINT  */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  IFERRORM1(sigaction(SIGINT, &sa, NULL));
  
  
  /* Check args */
  while((opt = getopt(argc, argv, optstring)) != -1){
    switch (opt){
      case 'i':
	device = optarg;
	printf("Network device found: %s\n", device);
	break;
      case 'v':
	verbose = 1;
	printf("verbose mode\n");
	break;
      }
  }
  if (device == NULL){
    printf("sonda: errore parametri\n"
	   "\t inserire opzione \"-i\" seguita dal nome dell'interfaccia di rete\n");
    exit(EXIT_FAILURE);
  }
  /* </Check args> */  
  

  /* Handle di cattura */
  handle = pcap_open_live(device, snaplen, promisc, timeout, errbuf);
  IFERRORNULL(handle, errbuf);

  /* Link-layer header type */
  datalink_type = pcap_datalink(handle);
  datalink_descr = pcap_datalink_val_to_description(datalink_type);
  IFERRORNULL(datalink_descr, "errore datalink");
  if (datalink_type != DATALINK_TYPE){
    printf("sonda: intestazione di livello collegamento non riconosciuta\n");
    exit(EXIT_FAILURE);
  }
  printf("Link-layer header: %s\n", datalink_descr);

  
  /* Preparazione richiesta cambio frequenza  */
  IFERRORM1((sockfd = socket(PF_INET, SOCK_DGRAM, 0)));
  strcpy(iwr.ifr_ifrn.ifrn_name, device);  
  
  while(1){
    iwr.u.freq.m = *(frequencies + index);
    iwr.u.freq.e = 6;
    /* Set frequenza scheda di rete */
    IFERRORM1(ioctl(sockfd, SIOCSIWFREQ, &iwr));
    
    _callback(handle, execution_time, verbose);

    index++;
    if (index == 13){
      /* "clean" controlla la consistenza della struttura rispettando il timeout indicato */
      clean(&access_points, clean_timeout, verbose);
      make_json(access_points);
      index = 0;
    }
  }    
}
