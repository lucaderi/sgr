
/*
 **********************************************************************
 ** Sniffit.c -- Implementation of Sniffit file included "Sniffit.h" **
 **                                                                  **
 ** Created: 09/07/2009  SGR project                                 **
 **                                                                  **
 ** Sniffit is a tool that reads packets live or from a pcap file    **
 **                                                                  **
 ** By Giuseppe Di francesco  <difrance@cli.di.unipi.it>             **
 **                                                                  **
 **                                                                  **
 **********************************************************************
 */

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <sys/mman.h>
#include "Sniffit.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//define
#define IFERROR(s,m)  if((s)==-1) {perror(m); exit(errno);} /* stampa errore                             */
#define IFERROR3(s,m,c)  if((s)==-1) {perror(m); c;}        /* stampa  errore ed esegue c                */
#define MAX_BYTE_TO_CAPTURE 1500                            /* MTU                                       */
#define N 10                                                /* numero di code e di conseguenza di thread */
#define HASHSIZE 40                                         /* dimensione hashtable multipla di N        */ 
#define SPINLOCK_UNLOCKED    1                              /* spinlock                                  */   
#define SPINLOCK_LOCKED      0                              /* spinlock                                  */

//var globali
pcap_t *in_pcap; 
int datalink;                            /* tipo di datalink                                           */
int count_packet;                        /* conta il numero totali di pacchetti con cui aggiornare rrd */
int *pkt_count;                          /* mapparla con mmap shared memory                            */
int live=0;                              /* indica se sniffa in modalità live                          */  
int tcp_packet,udp_packet;               /* # tcp # udp aggiornano rrd                                 */
pcap_dumper_t * file;                    
char *in_file = NULL;                    /* file in cui leggere i pacchetti catturati offline          */
int termina=0;                           /* indica la terminazione nel caso offline                    */
coda *array[N];                          /* array di code                                              */
pthread_t array_thread[N];               /* array di thread che leggono dalle code, una per ogni coda  */
static struct nlist *hashtab[HASHSIZE];  /* tabella dei puntatori                                      */
pthread_spinlock_t lock[HASHSIZE];       /* dichiaro gli spinlock uno per ogni cella della tabella     */ 
char *r=NULL;                            /* nome del file rrd                                          */
char *g=NULL;
struct timespec abstime;                 /* per variabile condizione timed_wait                        */ 
pthread_spinlock_t lock1; 
coda *cod;                               /* coda                                                       */
//msg messaggio;                         /* definisco il messaggio                                     */
pthread_t my_thread[N];
msg m;

//creo coda
coda * creaCoda(int capacity) { 
   coda * c=(coda*)malloc(sizeof(coda));
   c->capacity=capacity;
   c->head=-1;
   c->tail=-1;
   return c;
}
//controllo se la coda è vuota
bool isEmpty(coda * c) {
   return (c->head== -1); 
}
//controllo se coda piena
bool isFull(coda * c) {
   if (c == NULL)  return false;
   if (isEmpty(c)) return false;
   return (c->head == ((c->tail+1)%c->capacity));
}
//inserisco messaggio nella coda
bool enqueue(msg *mess, coda * c) {
   if (isFull(c)) return false;
   c->tail=(c->tail+1)%c->capacity;
   memcpy(&(c)->buffer[c->tail],mess, sizeof(struct msg));
   if (c->head == -1) {c->head = c->tail;}
   pthread_cond_signal (&c->notempty);  //sveglio eventuali thread in attesa su coda vuota
   return true;
}	
//estraggo messaggio dalla coda
msg* dequeue(coda * c) {
   if (isEmpty(c)) { return ;}
   m = c->buffer[c->head];
   c->head = (c->head+1)%c->capacity;
   if (c->head == (c->tail+1)%c->capacity) {
       c->head = -1;
       c->tail = -1;
   }
   return &m;
}
//funzione di hash
int funzHash(char *key, int n) {  
    int i=0;
    int entry=0;
    for(i=0; i < strlen(key);i++ ){
         entry = ((entry+((int)key[i])) % n);
         if (entry < 0) {
             entry += n;
         }
    }
    return entry;
}

/* ************************************* */

static void help() {
  printf("Sniffit [-l]  -i <interface> [-r] <file .rrd> [-g]    \n"); 
  printf("         -l             | live capture                \n");
  printf("         -f <file>.pcap | Pcap file by read           \n");
  printf("         -i <interface >| interface for capture       \n");
  printf("         -r <file>.rrd  | rrd file                    \n");
  printf("         -g             | graphic                     \n");
  printf("Example: Sniffit -l -i eth0  -r myrrdtool.rrd  -g     \n");
  printf("                                                      \n");
  printf("This tool that reads packets live or from a pcap file \n");
  exit(0);
}

/* ************************************* */

void processPacket(u_char *_deviceId,const struct pcap_pkthdr *h,const u_char *p) {
  int offset = 0, hlen;
  int rc,plen;
  struct ether_header ehdr;
  struct ip ipp;
  struct udphdr up;	
  u_short eth_type;
  int k=0;
  char *c;
  msg messaggio;    /* definisco il messaggio */
  struct pcap_pkthdr *h1 = (struct pcap_pkthdr *)h;
  
  //inserisco il numero di byte del pacchetto nella mia struttura messaggio
  messaggio.packet_bytes = h->caplen;

  if(datalink == DLT_EN10MB) {
    offset = 0;
  }else if(datalink == 113 /* Linux cooked */) {
    offset = 16;
  }
  hlen = offset;
  
  //livello datalink
  if(datalink == 113 /* Linux cooked */) {
    eth_type = 0x0800;
  } else {
    memcpy(&ehdr, p + hlen, sizeof(struct ether_header));
    hlen += sizeof(struct ether_header);
    eth_type = ntohs(ehdr.ether_type);

    if(hlen >= h->caplen) return; /* Pkt too short */
  }
  
  //livello ip
  if(eth_type == 0x0800 /* IP */) {
    int len;
    struct timeval tss;
    tss.tv_sec= h1->ts.tv_sec;
    tss.tv_usec=h1->ts.tv_usec;
    c = asctime(localtime(&tss.tv_sec));

    //inserisco il timestamp nella mia struttra
    messaggio.timestamp=tss.tv_sec;
  
    //inserisco l'indirizzo ip sorgente
    messaggio.ip_src=ipp.ip_src.s_addr;
   
    //inserisco l'indirizzo ip destinatario
    messaggio.ip_dst=ipp.ip_dst.s_addr;  

    //conto il numero di pacchetti	
    count_packet++;	
    memcpy(&ipp, p+hlen, sizeof(struct ip));

    if(ipp.ip_v != 4) return; /* IPv4 only */

    hlen += ((u_int)ipp.ip_hl * 4);
    
    if(hlen >= h->caplen) return; /* Pkt too short */   		
    
    //livello trasporto
    if(ipp.ip_p==IPPROTO_TCP){ // oppure ==6
       struct tcphdr tcp;
       tcp_packet++;   
       memcpy(&tcp,p+hlen,sizeof(struct tcphdr));	
	
       //inserisco gli indirizzi ip nella mia struttura  
       messaggio.s=strdup(inet_ntoa(ipp.ip_src));
       messaggio.d=strdup(inet_ntoa(ipp.ip_dst));
    
       //inserisco porta sorgente e destinatario nel caso di protocollo tcp
       messaggio.source=ntohs(tcp.source);
       messaggio.dest = ntohs(tcp.dest);

       //setto il protocollo
       messaggio.protocol=6;   
     }
     if(ipp.ip_p==IPPROTO_ICMP) {// oppure ==1
	printf(" ICMP ");
 	struct icmphdr icmp;
	memcpy(&icmp,p+hlen,sizeof(struct icmphdr));
	messaggio.protocol=1;     
      }
      if(ipp.ip_p == IPPROTO_UDP) { // 17
         char *payload;
	 udp_packet++;
         memcpy(&up,p+hlen,sizeof(struct udphdr));   
	
         messaggio.protocol = 17;  /* assegno il protocollo */

	 //inserisco gli indirizzi ip nella mia struttura	
	 messaggio.s=strdup(inet_ntoa(ipp.ip_src)); /* assegno gli indirizzi ip */
	 messaggio.d=strdup(inet_ntoa(ipp.ip_dst));

         //inserisco porta sorgente e destinatario nel caso di protocollo udp
         messaggio.source = ntohs(up.source);
         messaggio.dest = ntohs(up.dest);

         plen = h->caplen - hlen; 
         if(plen <= 0) return; /* Pkt too short */
       }        
    }
    //qui devo costruirmi la kiave k e inserire il messaggio nella coda esatta  k mod N
    int key_ip_src=funzHash(messaggio.s,N);
    int key_ip_dst=funzHash(messaggio.d,N);
   
    //stabilisco in che coda inserire il mess
    int  key = (messaggio.protocol+key_ip_src+key_ip_dst+messaggio.source+messaggio.dest)%N;
  
    //inserisco mess nella coda di indice key
    IFERROR(enqueue(&messaggio,array[key]),"errore nell'inserimento della coda");  
}

/* ************************************* */

//routine Luca's Deri
void changeUser() {
  struct passwd *pw = NULL;
  if(getuid() == 0) {
    // We're root 
    char *user;
    pw = getpwnam(user = "nobody");

    if(pw != NULL) {
      if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
	printf("Unable to change user to %s [%d:%d]: sticking with root\n", user, pw->pw_uid, pw->pw_gid);      
      else
	printf("n2disk changed user to %s\n", user);
    }
  }
}

/**************    RRDTOOL   *************************************/
/* crea database rrd */
void create_rrd(){
   char cmd[1024];
   char diritti[1024];
   sprintf(cmd," rrdtool create %s --step 1  DS:info_packet:COUNTER:10:0:U RRA:AVERAGE:0.5:1:50000 RRA:MIN:0.5:1:50000 RRA:MAX:0.5:1:50000              DS:tcp_packet:COUNTER:10:0:U  RRA:AVERAGE:0.5:1:50000  DS:udp_packet:COUNTER:6:0:U  RRA:AVERAGE:0.5:1:50000",r); 
   system(cmd); 	
   sprintf(diritti," chmod 777 %s",r);
   system(diritti);
}

/* crea grafico rrd */
void graph_rrd(){
   char cmd[1024]; 
sprintf(cmd,"rrdtool graph %s.png --start=end-1000seconds -t             'TCP/UDP packets' -v 'packets/second' --color=BACK#CCCCCC --color=CANVAS#9F9191 --color=SHADEB#9999CC DEF:in=%s:info_packet:AVERAGE AREA:in#FFFF55:Total_Packet    DEF:inn=%s:tcp_packet:AVERAGE       			      LINE1:inn#0000FF:Tcp DEF:udp=%s:udp_packet:AVERAGE AREA:udp#00AA00:Udp AREA:in#ff000030 ",g,r,r,r);//AREA:in#ff000030 AREA:inn#00ff0030",g,r,r,r); 
   system(cmd);
}
/* aggiorna database round robin */
void update_rrd(){
   char cmd[1024];
   sprintf(cmd," rrdtool update %s  N:%d:%d:%d",r,count_packet,tcp_packet,udp_packet);
   system(cmd);
   if(g != NULL ){graph_rrd();}   /* se attivato fa il grafico ogni aggiornamento */
   alarm(1);
}

/* *************     THREAD FOR CAPTURE    ************* */
 
//thread offline
 void* myfunz (void* arg){
    IFERROR(pcap_loop(in_pcap, -1, processPacket, NULL),"errore nella pcap_loop");
    pcap_close(in_pcap);
    termina = 1;      
     
}
 //thread online
 void* myfunzione (void* arg){
     if(pcap_loop(in_pcap,0,processPacket,(u_char *)file)==-1){
        printf("Errore loop: %s\n",pcap_geterr(in_pcap));
        return ;
     }	  
     pcap_dump_close(file);
     pcap_close(in_pcap);
     termina=1;// non ha senso metterlo
}

/* **************  THREAD FOR READ  ******************* */

void *read_(void * arg){

    // qui i trhead leggono dalle code e inseriscono nella tabella hash
    int co= (int)arg; 
    while( termina != 1){
	int ret;
        ret = sched_yield();
	if(!isEmpty(array[co])){  
	    msg *mio = dequeue(array[co]);
            
            //costruisco la chiave
            int key_ip_src=funzHash(mio->s,HASHSIZE);
            int key_ip_dst=funzHash(mio->d,HASHSIZE);

            //stabilisco in che coda inserire il mess
            int key = (mio->protocol+key_ip_src+key_ip_dst+mio->source+mio->dest)%HASHSIZE;

            //inserisco nella tabella hash
            IFERROR(install(key, mio),"errore nell'inserimento  della tabella\n");
       
         } else pthread_cond_wait(&(array[co])->notempty,&(array[co])->lock);
    }	
    pthread_exit(NULL);
}
	
/* ************  THREAD SPAZZINO  ****************************  */

void* myDelete (void* arg){
   while(termina!=1){
	//sleep(1);
	if((hashtbl_remove() != 0))
	    printf("errore nela rimozione\n");
   }    
   pthread_exit(NULL);
}

/* **************  HASHTABLE ****************** */

//ricerca nella tabella hash
struct nlist *lookup(int key, msg *mess){
    struct nlist *np;
    for(np = hashtab[key] ; np != NULL ; np = np->next)
         if ((mess->protocol == np->data->protocol) && (strcmp(mess->s,np->data->s) == 0) &&  
               (strcmp(mess->d,np->data->d) == 0)   && (mess->source == np->data->source)&&                        
               (mess->dest == np->data->dest)){ //devo aggiornare
               np->flusso->dir=0; mess->dir =0;return np;  // trovata direzione sorg->dest
         }else if((mess->protocol == np->data->protocol) && (strcmp(mess->s,np->data->d) == 0) &&  
                 (strcmp(mess->d,np->data->s) == 0)   && (mess->source == np->data->dest)&&                        
                 (mess->dest == np->data->source)){
		  np->flusso->dir=1; mess->dir =1;return np;}  // trovata direzione dest->sorg
     return NULL; // nn trovata
}
int install(int key,msg * mess){
    struct nlist *np;
	
   //spinlock 
   pthread_spin_lock(&lock[key]);
 
   if((np = lookup(key, mess)) == NULL ){ //devo aggiungere
        np = (struct nlist *) malloc (sizeof(*np));
 	if( np == NULL )
	    return -1;
        np->data = (struct msg*)malloc(sizeof(*mess));  //da usare la calloc che iniziazza i valori a 0 
	memcpy(np->data,mess, sizeof(msg));

        np->flusso = (struct flow*)malloc(sizeof(FLOW)); // o * // da usare la calloc che inzializza i valori a 0
	if(np->flusso->dir==0){
           np->flusso->pkt_c_s = 1;         
	   np->flusso->pkt_b_s = np->data->packet_bytes;
           np->flusso->timestamp_first = np->data->timestamp;
           np->flusso->pkt_c_d = 0;         
	   np->flusso->pkt_b_d = 0;
        }else{
           np->flusso->pkt_c_d = 1;         
	   np->flusso->pkt_b_d = np->data->packet_bytes;
           np->flusso->timestamp_first = np->data->timestamp;
           np->flusso->pkt_c_s = 0;         
	   np->flusso->pkt_b_s = 0;
        }
        np->flusso->timestamp_last = np->data->timestamp;;
	np->next = hashtab[key];
	hashtab[key] = np;
    }else{ //devo aggiornare
	time_t now;     
        now=time(NULL);
        double diff=0;	
	if(np->flusso->dir == 0){
	   np->flusso->pkt_c_s++;
	   np->flusso->pkt_b_s = np->flusso->pkt_b_s + mess->packet_bytes;
	   np->flusso->timestamp_last = now;
  	 }else{
	   np->flusso->pkt_c_d++;
	   np->flusso->pkt_b_d = np->flusso->pkt_b_d + mess->packet_bytes;
	   np->flusso->timestamp_last = now;
         }
	if( (np->data=mess) == NULL)
	  return -1;
     }   //spinlock
         pthread_spin_unlock(&lock[key]);
     return 0;  
}
int hashtbl_remove()
{
   struct nlist *np, *prev_np;
   int n; 
   for(n=0; n < HASHSIZE; n++) {
       np = hashtab[n];
       prev_np = NULL;
       for(np ; np !=NULL; np = np->next){	
	   time_t now;
           now = time(NULL);
           double diff=0;
	   double diff1=0;
	   //qui devo controllare il timestamp 
		if( (diff=difftime(now, np->flusso->timestamp_first) >= 1)  ||// controllo da quanto è attivo    
                    ( (diff1=difftime(now,np->flusso->timestamp_last) >= 0) )){ //da quanto è inattivo 
             
		    fprintf(stdout,"\n FLUSSO ");

fprintf(stdout,"prot: %d ip_sorg: %s  ip_dest:%s  porta_s:%d  porta_d:%d  #pkt_s:%d  #bytes_s:%d  #pkt_d: %d  #bytes_d:%d",np->data->protocol, np->data->s,np->data->d,np->data->source,np->data->dest,np->flusso->pkt_c_s, np->flusso->pkt_b_s,np->flusso->pkt_c_d, np->flusso->pkt_b_d );

                    pthread_spin_lock(&lock[n]);
			
		    if(prev_np) prev_np->next = np->next;
		    else hashtab[n] = np->next;
		    
                    free(np);
                    
                    pthread_spin_unlock(&lock[n]);						
		    return 0;
		}
		prev_np=np;
	    }  
        }
	return 0;
}

/* ************************************************** */

int main(int argc, char* argv[]) {

  int err;
  char  errbuf[256];
  char c, *bpf_filter = "udp or tcp or icmp";
  char *dev=NULL;
  int i=1;
  bpf_u_int32 *net,  *mask;
  char t;
  char permessi[1024];

  //thread per pcap_loop 
  pthread_t thread_cattura_offline;
  pthread_t thread_cattura_online;
 
  //thread per la rimozione di flussi
  pthread_t remove_flow;

  //creo le code buffer per la lettura dei pacchetti
  for(i=0; i < N ; i++){
      array[i]=creaCoda(CAPACITY);
      pthread_cond_init (&array[i]->notempty, NULL);
      pthread_mutex_init (&array[i]->lock, NULL);
  }

  //creo i thread per leggere dalle code
  for(i=0; i < N ; i++){
	int id=i;
      pthread_create(&array_thread[i], NULL, read_, (void*)id);
   }
    int d;
   // inizializzo gli spinlock della tabella hash 
   for( d=0; d < HASHSIZE; d++){
      lock[d] = SPINLOCK_UNLOCKED;
  }

if(argc < 2) 
    help();
  
  while((c = getopt(argc, argv, "lf:r:i:g:")) != -1) {
    switch(c) {
    case 'r':
      r = strdup(optarg);
      break;
    case 'l':
      live = 1;
      break;
    case 'f':
      in_file = strdup(optarg);
      break;
    case 'i':
      dev = strdup(optarg);
      break;
    case 'g':
      g = strdup(optarg);
      break;

    }
  }

 /* ***************************** */

  if(live == 1) {
     printf("cattura LIVE ");
	if(dev ==NULL){	
	   if(dev = pcap_lookupdev(errbuf))
    	      printf("Device: %s\n",dev);
	   else {
    	      printf("Errore lookupdev: %s\n",errbuf);
    	      exit(0);
	   }
	}
	/* Open the session in promiscuous mode */
	if(!(in_pcap=pcap_open_live(dev,MAX_BYTE_TO_CAPTURE,1,0,errbuf))) {
	    printf("Errore open_live: %s\nx	",errbuf);
  	    return;
        }
 	datalink=pcap_datalink(in_pcap);

        //applico il filtro per la cattura di paccketti tcp , udp or icmp
        if(bpf_filter && (bpf_filter[0] != '\0')) {
        struct bpf_program fcode;

        if((pcap_compile(in_pcap, &fcode, bpf_filter, 1, 0) < 0) || (pcap_setfilter(in_pcap, &fcode) < 0)) 
           printf("Unable to set filter %s. Filter ignored.\n", bpf_filter);
        else
           printf("Filter '%s' set succesfully\n", bpf_filter);
        }
        
        if( r != NULL){	
         //creo il database rrd
         create_rrd();  
                  
	 if(g != NULL){
          //stampo il grafico 
          graph_rrd();
          //assegno i permessi
	  sprintf(permessi," chmod 777 %s.png",g);
          system(permessi);  
         }
         //faccio partire l'handler per l'update di rrdtool
         signal(SIGALRM, update_rrd);
         alarm(1);
        }
        //creo thread per la cattura on line
        if (err=pthread_create(&thread_cattura_online, NULL, myfunzione, NULL)  != 0 ) { printf(" qui mi dai errore?????");/* gest errore */ }
      
	//toglie diritti di root
	changeUser();

        if (err=pthread_create(&remove_flow, NULL, myDelete, NULL)  != 0 ) { printf("errore nella creazione thread cattura offline");} 
        // join sui thread creati  
        if (err=pthread_join(thread_cattura_online, NULL) !=0) { printf(" qui mi dai errore?????");/* gest errore */ }       
        if (err=pthread_join(remove_flow, NULL)  != 0 ) { printf("errore nella join del thread offline");} 	
	
   }else{
      // off line
	
  if((in_file == NULL))
    help();
      in_pcap = pcap_open_offline(in_file, errbuf);
      if(in_pcap == NULL) {
         printf("pcap_open: %s\n", errbuf);
         return(-1);
       }   
      //applico il filtro per la cattura di paccketti tcp , udp or icmp
      if(bpf_filter && (bpf_filter[0] != '\0')) {
      struct bpf_program fcode;

      if((pcap_compile(in_pcap, &fcode, bpf_filter, 1, 0) < 0) || (pcap_setfilter(in_pcap, &fcode) < 0))
        printf("Unable to set filter %s. Filter ignored.\n", bpf_filter);
      else
        printf("Filter '%s' set succesfully\n", bpf_filter);
      }
      datalink = pcap_datalink(in_pcap);

      printf("\n timestamp /protocollo/ ip src: porta/ip dest:porta");

      //creo il thread per la cattura offline
      if (err=pthread_create(&thread_cattura_offline, NULL, myfunz, NULL)  != 0 ) { printf("errore nella creazione thread cattura offline");} 
      if (err=pthread_create(&remove_flow, NULL, myDelete, NULL)  != 0 ) { printf("errore nella creazione thread cattura offline");}
      if( r != NULL){	
         //creo il database rrd
         create_rrd();  
                  
	 if(g != NULL){
           //stampa il grafico 
           graph_rrd(); 
           // assegna permessi 
           sprintf(permessi," chmod 777 %s.png",g);
           system(permessi);  
         }
         //faccio partire l'handler per l'update di rrdtool
         signal(SIGALRM, update_rrd);
         alarm(1);
      }
    if (err=pthread_join(thread_cattura_offline, NULL)  != 0 ) { printf("errore nella join del thread offline");} 	      
     // termina = 1;       
      if (err=pthread_join(remove_flow, NULL)  != 0 ) { printf("errore nella join del thread offline");}      
         
      //aspetto la fine dei thread 
      for(i=0; i < N ; i++){
        if (err=pthread_join(array_thread[i], NULL)  != 0 ) { printf("errore nella join del thread offline");} 
      } 
    }
   //stampo il numero di pacchetti
   printf("\nTOTAL PACKETS is : %d\n",count_packet);
   printf("Done\n");
   return(0);
}
