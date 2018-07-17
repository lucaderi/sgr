/* ---------------------------------------------------------------------- */
/* 								HOKER: local network HOst tracKER                    		*/
/* Autori: Mario Coco - 517558, Federico Finocchio - 516818               */
/* Compilare con: gcc main.c map.c -o hoker -lpcap -pthread 							*/
/* Utilizzo: sudo ./hoker <interfaccia>                                		*/
/* Eseguire con permessi di root!                                         */ 
/* ---------------------------------------------------------------------- */

#include "includes.h"

#define ARP_REPLY 2
#define MAXBYTES2CAPTURE 1500
#define SEND_INTERVAL 2000
#define T_ALARM 3
#define BROADCAST_MAC 0xff


bpf_u_int32 netaddr=0, mask=0;       	/* Indirizzo di rete e maschera   */ 
char* interface;										 	/* Interfaccia di rete					 	*/
pcap_t *descr = NULL;                	/* Handler interfaccia di rete    */
map_void_t map;                      	/* Hashmap host in rete           */
eth_pkt_t *eth_pkt = NULL;           	/* Puntatore al frame ethernet    */
unsigned char *source_mac_addr;      	/* Indirizzo MAC locale           */
unsigned char *mac;                  	/* Stringa indirizzo MAC target   */
unsigned char *s_mac;                	/* Stringa indirizzo MAC locale   */
net_stats_t *stats;										/* Struttura statistiche di rete	*/
unsigned long first_ip;              	/* Indirizzo di rete              */
unsigned long last_ip;               	/* Ultimo indirizzo               */
hash_node_t **table;									/* Struttura ordinata nodi				*/ 
unsigned long ip_count;               /* Numero indirizzi nel blocco  	*/
int notused;


/* ------------------------ Funzioni di utilità ------------------------ */


/* Costruisce stringa a partire da indirizzo MAC */
void macBuilder(unsigned char *str, u_char *mac) {
  sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


/* Funzione per la formattazione della stampa */
void printInfo() {

	printf(" -------------------------------------------------------------------------------\n");
	printf("| Host			| Indirizzo MAC			| Stato			|\n");
	printf(" -------------------------------------------------------------------------------\n");

	for(int i=0; i<ip_count; i++) {
		if(table[i]!=NULL) {
			printf("| %d.%d.%d.%d\t\t", table[i]->spa[0], table[i]->spa[1], table[i]->spa[2], table[i]->spa[3]);
			printf("| %02X:%02X:%02X:%02X:%02X:%02X\t\t",table[i]->sha[0], table[i]->sha[1], table[i]->sha[2],
      	table[i]->sha[3], table[i]->sha[4], table[i]->sha[5]);

  		if(table[i]->lastUsed == 1) {
     	 printf("| Online\t\t|\n");
     	 table[i]->lastUsed = 0;
     	 stats->online++;
  		}
  		else
    		printf("| Offline\t\t|\n");
		}
	}
	printf(" -------------------------------------------------------------------------------\n");
	printf("Utenti totali: %d\n",stats->len);
  printf("Utenti online: %d/%d\n", stats->online, stats->len);
  stats->online = 0;

}


/* Funzione per il recupero degli host nella hashmap */
void getHostInfo() {

  const char* key;	/* Chiave di iterazione */
	char *string;			/* Stringa IP mittente 	*/
	stats->len = 0;

	/* Inizializza iteratore e itera sugli elementi della hasmap */
  map_iter_t iter = map_iter(&map);
  while(key = map_next(&map, &iter)) {

    stats->len++;

		/* Generico nodo hasmap */
    hash_node_t *node = (hash_node_t*)(*map_get(&map, key));

		/* Recupera IP mittente e lo utilizza per indicizzare la sruttura ordinata */
		CHECK_T_ALLOC(string, malloc(20*sizeof(char)), "malloc fallita");
	  sprintf(string, "%d.%d.%d.%d", node->spa[0], node->spa[1], node->spa[2], node->spa[3]);
	  struct in_addr address;
	  inet_aton(string, &address);
		free(string);
	  unsigned long index = ntohl(address.s_addr) - first_ip;
	  table[index]=node;
		
  }

	printInfo();

} 


/* Funzione per liberare la memoria allocata */
void freeMem() {

	const char* key;	/* Chiave di iterazione */

	free(mac);
  free(s_mac);
	free(table);
	free(stats);

  map_iter_t iter = map_iter(&map);
  while(key = map_next(&map, &iter)) {
    hash_node_t *node = (hash_node_t*)(*map_get(&map, key));
    free(node);
  }

	map_deinit(&map);

}
/* --------------------------------------------------------------------- */


/* Funzione invocata da pcap_loop per processare pacchetti ricevuti */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt) {

  /* Pacchetto ricevuto */
  eth_pkt = (eth_pkt_t*)pkt;

  /* Costruisce stringhe relative a MAC target e MAC locale */
  macBuilder(mac, eth_pkt->tha);
  macBuilder(s_mac, source_mac_addr);

  /* Inserisce informazioni sugli host nella hashmap se il pacchetto ricevuto 
     è un ARP_REPLY con destinatario MAC locale */
  if(ntohs(eth_pkt->oper) == ARP_REPLY && strcmp(s_mac, mac) == 0) {

    /* Costruisce stringa relativa a MAC sorgente */
    macBuilder(mac, eth_pkt->sha);

		/* Costruisce elemento hashmap */
		hash_node_t *node;
		CHECK_T_ALLOC(node, malloc(sizeof(hash_node_t)), "malloc fallita");
		memcpy(node->sha, &eth_pkt->sha, sizeof(node->sha));
		memcpy(node->spa, &eth_pkt->spa, sizeof(node->spa));
		node->lastUsed = 1;
      
    /* Inserisce elemento nella hashmap */
    CHECK_T_MENO1(notused, map_set(&map, mac, node), "map_set fallita");

  }
}


/* Funzione thread per invio richieste ARP */
void* discoverer(void* arg) {

  eth_pkt_t packet;                                 /* Frame ethernet               							*/
	int fd;                                           /* File descriptor socket       							*/
  struct ifreq ifr;                                 /* Struttura informazioni interfaccia di rete	*/
	struct in_addr address;                           /* Struttura per indirizzo IP    							*/
  unsigned char frame[sizeof(eth_pkt_t)];           /* Frame da inviare sulla rete  							*/
	struct ifaddrs *ifap, *ifa;												/* Struttura informazioni interfaccia di rete	*/
  struct sockaddr_in *source_ip_addr;								/* Struttura per indirizzo IP locale					*/

  /* Imposta nome interfaccia di rete */
  size_t if_name_len=strlen(interface);
  memcpy(ifr.ifr_name,interface,if_name_len);
  ifr.ifr_name[if_name_len]=0;

  CHECK_T_MENO1(fd, socket(AF_INET,SOCK_DGRAM,0), "errore apertura socket");

  CHECK_T_MENO1(notused, ioctl(fd,SIOCGIFHWADDR,&ifr), "errore ioctl"); 

  /* Recupera indirizzo MAC locale */
  source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;

  CHECK_T_MENO1(notused, close(fd), "close fallita");

  /* Recupera indirizzo IP relativo ad interfaccia di rete in interface */
  CHECK_T_MENO1(notused, getifaddrs (&ifap), "getifaddrs fallita");
  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->if_addr == NULL)
				continue;
      if (ifa->ifa_addr->sa_family==AF_INET && strcmp(ifa->ifa_name, interface)==0) {
         source_ip_addr = (struct sockaddr_in *) ifa->ifa_addr;
				 memcpy(&packet.spa, &source_ip_addr->sin_addr, sizeof(packet.spa));
      }
  }
  freeifaddrs(ifap);

  /* Imposta MAC sorgente e destinatario in header collegamento */
  memcpy(&packet.ethdr.ether_shost, source_mac_addr, sizeof(packet.ethdr.ether_shost));
  memset(&packet.ethdr.ether_dhost, BROADCAST_MAC, sizeof(packet.ethdr.ether_dhost));

  /* Imposta informazioni in pacchetto ARP */
  packet.ethdr.ether_type=htons(ETH_P_ARP);
  packet.htype=htons(ARPHRD_ETHER);
  packet.ptype=htons(ETH_P_IP);
  packet.hlen=ETHER_ADDR_LEN;
  packet.plen=sizeof(in_addr_t);
  packet.oper=htons(ARPOP_REQUEST);
  memset(&packet.tha, 0, sizeof(packet.tha)); 
  memcpy(&packet.sha, source_mac_addr, sizeof(packet.sha));

  /* Cicla sugli indirizzi IP presenti nel blocco ed invia richieste ARP */
	for (unsigned long ip = first_ip; ip <= last_ip; ++ip) {
   
		printf("%ld%%\r", 100*(ip-first_ip)/ip_count);

		/* Imposta indirizzo IP destinatario in pacchetto ARP */
		unsigned long theip = htonl(ip);
		address.s_addr = (theip);
    memcpy(&packet.tpa, &address.s_addr, sizeof(packet.tpa));

    /* Costruisce frame ethernet e lo invia sulla rete */
    memcpy(frame, &packet, sizeof(eth_pkt_t));
    CHECK_T_MENO1(notused, pcap_inject(descr, frame, sizeof(frame)), "errore pcap_inject");

    /* Attende prima di inviare una nuova richiesta */
    CHECK_T_MENO1(notused, usleep(SEND_INTERVAL), "usleep fallita");

	}

}


/* Funzione thread per ricezione risposte ARP */
void* sniffer(void* arg) {
  CHECK_T_MENO1(notused, pcap_loop(descr, -1, processPacket, NULL), "pcap_loop fallita");
}


/* Funzione per callback segnale SIGALRM */
void alarm_handler(int sig) {
  pcap_breakloop(descr);
}


int main(int argc, char *argv[]) {

  int i=0;
  struct bpf_program filter;           	/* Filtro programma BPF          */ 
  struct pcap_pkthdr pkthdr;           	/* Informazioni pacchetto        */
  pthread_t dis;                       	/* Thread invio richieste ARP    */
  pthread_t snif;                      	/* Thread ricezione risposte ARP */
  char errbuf[PCAP_ERRBUF_SIZE];       	/* Buffer errore                 */
	char scelta;													/* Scelta utente 								 */

  if (argc != 2) { 
      printf("USAGE: hoker <interface>\n"); 
      exit(1); 
  }
  interface=argv[1];

	/* Inizializza strutture dati */
  memset(errbuf,0,PCAP_ERRBUF_SIZE);
	CHECK_ALLOC(mac, malloc(18*sizeof(char)), "malloc fallita");
	CHECK_ALLOC(s_mac, malloc(18*sizeof(char)), "malloc fallita");
  CHECK_ALLOC(stats, calloc(1,sizeof(net_stats_t)), "calloc fallita");
  map_init(&map);

   /* Apre device di rete per cattura di pacchetti */
  CHECK_NULL(descr,pcap_open_live(interface, MAXBYTES2CAPTURE, 0, 1000, errbuf), "Errore in pcap_open_live");

  /* Recupera info dal device di rete */ 
  CHECK_MENO1(notused,pcap_lookupnet(interface, &netaddr, &mask, errbuf), "Errore in pcap_lookupnet");

  /* Compila l'espressione filtro in un programma BPF */
  CHECK_MENO1(notused, pcap_compile(descr, &filter, "arp", 1000, mask), "Errore in pcap_compile");

  /* Imposta il filtro nel device di cattura */
  CHECK_MENO1(notused, pcap_setfilter(descr,&filter), "Errore in pcap_setfilter");

  /* Ricava indirizzi */
  first_ip = ntohl(netaddr & mask);
	last_ip = ntohl(netaddr | ~(mask));
	ip_count = last_ip - first_ip;

	/* Inizializza struttura ordinata */
	CHECK_ALLOC(table, malloc(sizeof(hash_node_t*)*ip_count), "malloc fallita");
  for(int i=0; i<ip_count; i++) {
    table[i] = NULL;
  }

  while(1) {

		printf("Inizio scansione\n");

    /* Crea thread sniffer */
    CHECK_OVER0(pthread_create(&snif,NULL,&sniffer,NULL),"pthread_create fallita\n");

    /* Crea thread per invio richieste ARP */
    CHECK_OVER0(pthread_create(&dis,NULL,&discoverer,NULL),"pthread_create fallita\n");

	  CHECK_OVER0(pthread_join(dis,NULL),"pthread_join fallita\n");

    /* Imposta timeout per interruzione pcap_loop */
    alarm(T_ALARM);
    signal(SIGALRM, alarm_handler);
    
    CHECK_OVER0(pthread_join(snif,NULL),"pthread_join fallita\n");

    /* Stampa [MAC - IP] degli host connessi alla rete */
    getHostInfo();

    printf("Effettuare nuova scansione? [S/n]\n");
		scanf(" %c", &scelta);
		printf("\n");
		if( scelta=='n' )
			break;
		else if( scelta!='S' && scelta!='s' ) {
			printf("Interrotto\n");
			break;
		}
  }

	freeMem();
		
  return 0; 

}
