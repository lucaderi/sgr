
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

#include <netdb.h>

#include <pwd.h>
#include <sys/types.h>

#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>

time_t tNow;


int num_pckt_ip = 0;
int num_pckt_udp = 0;
int num_pckt_tcp = 0;
int num_pckt_icmp = 0;

unsigned int sec;
char *rrdname = "moriTraff.rrd";
char *pngname = "moriTraff.png";
int graph_Number_alarm=0;
int refreshTime = 5;
	
int step=5;
int overstep=10;

pcap_t *in_pcap;
int datalink, verbose = 1, sock_fd;
struct sockaddr_in sofia_addr;


/* ******* Struttura di un host    ******* */
struct host
{
  char * ip;
  uint16_t port; 
};

/* ******* Struttura dati flusso:                                       ******* */
/* ******* numero pacchetti, bytes e tempi di arrivo iniziale e finale  ******* */
struct data
{
  uint32_t packets, bytes; 
  time_t first, last;
};

/* ******* Struttura flusso con quintupla (IPsrc, PortSrc, IPDst, PortDst, Protocollo)    ******* */
struct flow
{
  struct host * src, * dst;
  struct data * data_pckt; 
  char * protocol;
  struct flow * next;
};

/* ******* Struttura dell'hashtable    ******* */
struct hashtable
{
  int size;
  struct flow ** table; 
};

struct hashtable * copiaHash;//copia hashtable

/* ******* Crea l'hashtable    ******* */
struct hashtable * create_hash(int siz)
{
  struct hashtable * ret_hashtable;

  ret_hashtable = malloc(sizeof(struct hashtable));
  ret_hashtable->table = calloc(siz, sizeof(struct flow*));
  ret_hashtable->size=siz;
  
  return ret_hashtable;
}

/* ******* Calcola posizione dell'hashtable partendo dalla chiave   ******* */
int calcola_hash_value(uint32_t chiave, struct hashtable* hash)
{
  return chiave % hash->size;
}

/* ******* Aggiorna i flussi presenti nell'hashtable (e liste annesse)    ******* */
/* ******* Inserisce nuovi flussi nell'hashtable (e liste annesse)        ******* */
void insert(struct hashtable* hash, uint32_t chiave, char * protocol, char * ip_src, uint16_t port_src, char * ip_dst, uint16_t port_dst, uint32_t bytes, time_t timestamp)
{
   int index = calcola_hash_value(chiave, hash);
   struct flow * flusso = hash->table[index];

   while (flusso)
   {
   	if (!strcmp(flusso->protocol, protocol))
   	{
      		if ((!strcmp(flusso->src->ip, ip_src) && !strcmp(flusso->dst->ip, ip_dst)) || (!strcmp(flusso->src->ip, ip_dst) && !strcmp(flusso->dst->ip, ip_src)))
      		{
      	
              		if (((flusso->src->port == port_src) && (flusso->dst->port == port_dst)) || ((flusso->src->port == port_dst) && (flusso->dst->port == port_src)))
              		{
                  		flusso->data_pckt->packets++;
                  		flusso->data_pckt->bytes += bytes;
                  		flusso->data_pckt->last = timestamp;
                  		return;
              		}         
          	}
      	}
      	flusso = flusso->next;
   }

   struct host * host_t = malloc(sizeof(struct host));   
   struct host * host_t2 = malloc(sizeof(struct host));
   struct data * data_t = malloc(sizeof(struct data));
   struct flow * flow_t = malloc(sizeof(struct flow));
   
   host_t->ip = strdup(ip_src);            
   host_t->port = port_src;
   
   host_t2->ip = strdup(ip_dst);            
   host_t2->port = port_dst;
   
   data_t->packets = 1;            
   data_t->bytes = bytes;
   
   data_t->first = timestamp;            
   data_t->last = timestamp;
   
   flow_t->data_pckt = data_t;
   flow_t->protocol = strdup(protocol);
   flow_t->src = host_t;
   flow_t->dst = host_t2;
   
   flow_t->next = hash->table[index];
   hash->table[index] = flow_t;
}

/* ******* Stampa ed Elimina flussi dall'hashtable ******* */
/* ******* (e liste annesse se):                   ******* */
/*                                                         */
/* ******* 1) TLast - TFirst > Tempo step          ******* */
/* ******* 2) Tnow - TLast > Tempo step            ******* */
void refresh(struct hashtable* hash, int step, time_t tNow)
{
   struct flow * flusso = NULL;
   struct flow * flussoPrev = NULL;

   int dimention_hash= (int) hash->size;
   int i;
   
   
   for(i=0; i<dimention_hash; i++)
   {
      flusso = hash->table[i];
      flussoPrev = hash->table[i];
      
      while (flusso)
      {
          if( ( difftime(flusso->data_pckt->last, flusso->data_pckt->first) > (double) step) || ( difftime(tNow, flusso->data_pckt->last) > (double) step))
          {
              printf("FLUSSO (PRTCL=%s SRC IP=%s Port=%d, DST IP=%s Port=%d): --- Num Pckts=%d Num Bytes=%d ---\n", flusso->protocol, flusso->src->ip, flusso->src->port, flusso->dst->ip, flusso->dst->port, flusso->data_pckt->packets, flusso->data_pckt->bytes);
              free(flusso->protocol);
              free(flusso->src->ip);
              free(flusso->dst->ip);
              free(flusso->dst);
              free(flusso->src);
              free(flusso->data_pckt);
              if(flussoPrev == flusso)//caso testa (flussoPrev e flusso allineati)
              {
       	         hash->table[i] = flusso->next;
       	         free(flusso);
       	         flusso = hash->table[i];
       	         flussoPrev = NULL;
       	      }
       	      else//caso intermedio (flussoPrev e flusso NON allineati)
       	      {
                 flussoPrev->next = flusso->next;
                 free(flusso);
                 flusso = flussoPrev;
              }
              
          }
          if(flussoPrev != NULL)//caso intermedio (flussoPrev e flusso NON allineati)
          {
             flussoPrev = flusso;    
             flusso = flusso->next;
          }
          else//caso testa (flussoPrev e flusso allineati)
             flussoPrev = flusso;
             
      }

   
   }

   
}

/* **************** processPacket ********************* */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  int offset = 0, hlen;
  struct ether_header ehdr;
  struct ip ip;
  u_short eth_type;
  struct pcap_pkthdr *h1 = (struct pcap_pkthdr *)h;
  char *protocol;
  char * ipSrc, * ipDst;


 
  /******** LIVELLO II ********/
  if(datalink == DLT_EN10MB)//ETHERNET
  {
    offset = 0;
  }

  hlen = offset;

  if(datalink == DLT_EN10MB)
  {
    memcpy(&ehdr, p + hlen, sizeof(struct ether_header));
    hlen += sizeof(struct ether_header);
    eth_type = ntohs(ehdr.ether_type);

    if(hlen >= h->caplen) return; /* Pkt too short */
  }

  /******** LIVELLO III ********/
  if(eth_type == 0x0800 /* IP */) {//ETHERTYPE_IP
    memcpy(&ip, p+hlen, sizeof(struct ip));
    if(ip.ip_v != 4) return; /* IPv4 only */


    hlen += ((u_int)ip.ip_hl * 4);

    if(hlen >= h->caplen) return; /* Pkt too short */

    num_pckt_ip++;

    if (verbose) printf("NUM Packet IP=%d\n", num_pckt_ip);


    protocol = (getprotobynumber(ip.ip_p))->p_name;

    char * temp = inet_ntoa(ip.ip_src);
    int l = strlen(temp)+1;   
    ipSrc = malloc(l*sizeof(char)); 
    strncpy(ipSrc, temp, l);//vedere meglio warning
    
    temp=inet_ntoa(ip.ip_dst);
    l = strlen(temp)+1;
    ipDst = malloc(l*sizeof(char));    
    strncpy(ipDst, temp, l);//vedere meglio warning
    
    uint32_t chiave = ip.ip_src.s_addr + ip.ip_dst.s_addr;
    
    /* Convertire Timestamp */
    char *timestamp = (char *)ctime(&h1->ts.tv_sec);

    //UDP
    if(ip.ip_p == IPPROTO_UDP) {

      int plen;

      struct udphdr udp;

      memcpy(&udp, p+hlen, sizeof(struct udphdr));

      hlen += sizeof(struct udphdr);
      plen = h->caplen - hlen;

      if(plen <= 0) return; /* Pkt too short */

      num_pckt_udp++;

      insert(copiaHash, chiave, protocol, ipSrc, ntohs(udp.source), ipDst, ntohs(udp.dest), h->len, h->ts.tv_sec);
      if (verbose) 
      {
          printf("\n***********************************\n");
          printf(" NUM PACKET UDP=%d\n", num_pckt_udp);
          printf(" processPacket(p_len=%d, datalink=%d, DLT_EN10MB=%d)\n", h->len, datalink, DLT_EN10MB);
          printf(" Timestamp=%s \n", timestamp);

          printf(" PROTOCOLLO=%s\n src IP=%s dest IP=%s\n", protocol, ipSrc, ipDst);
          printf(" SRC PORT=%d DEST PORT=%d \n", ntohs(udp.source), ntohs(udp.dest));
          printf("***********************************\n\n");
      }
    }
    //TCP
    if(ip.ip_p == IPPROTO_TCP)
    {
      int plen;
      struct tcphdr tcp;

      memcpy(&tcp, p+hlen, sizeof(struct tcphdr));
      hlen += sizeof(struct tcphdr);
      plen = h->caplen - hlen;

      if(plen <= 0) return; /* Pkt too short */

      num_pckt_tcp++;

      insert(copiaHash, chiave, protocol, ipSrc, ntohs(tcp.source), ipDst, ntohs(tcp.dest), h->len, h->ts.tv_sec);
      if (verbose) 
      {
          printf("\n***********************************\n");
          printf(" NUM PACKET TCP=%d\n", num_pckt_tcp);
          printf("processPacket(p_len=%d, datalink=%d, DLT_EN10MB=%d)\n", h->len, datalink, DLT_EN10MB);
          printf("Timestamp=%s \n ", timestamp);

          printf("PROTOCOLLO=%s src IP=%s dest IP=%s\n", protocol, ipSrc, ipDst);

          printf("SRC PORT=%d DEST PORT=%d \n", ntohs(tcp.source), ntohs(tcp.dest));
          printf("***********************************\n\n");
      }
    }    
    //ICMP
    if(ip.ip_p == IPPROTO_ICMP) {//le porte vanno a zero

      int plen;

      struct icmphdr icmp;

      memcpy(&icmp, p+hlen, sizeof(struct icmphdr));

      hlen += sizeof(struct icmphdr);
      plen = h->caplen - hlen;
      if(plen <= 0) return; // Pkt too short 

      num_pckt_icmp++;

      insert(copiaHash, chiave, protocol, ipSrc, 0, ipDst, 0, h->len, h->ts.tv_sec);
      if (verbose) 
      {
          printf("\n********************************\n");
          printf(" NUM PACKET ICMP=%d\n", num_pckt_icmp);
          printf(" processPacket(p_len=%d, datalink=%d, DLT_EN10MB=%d)\n", h->len, datalink, DLT_EN10MB);
          printf(" Timestamp=%s \n", timestamp);

      //printf(" PROTOCOLLO=%s\n", protocol);
          printf("PROTOCOLLO=%s src IP=%s dest IP=%s\n", protocol, ipSrc, ipDst);
          printf("********************************\n\n");
      }
    }
	
  }
}

/* ********* Cambio utente *********** */
void changeUser() {
   struct passwd *pw = NULL;

   if(getuid() == 0) {
     /* We're root */
     char *user;

    pw = getpwnam(user = "giulio");

     if(pw != NULL) {
       if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
         printf("Unable to change user to %s [%d: %d]: sticking with root\n", user, pw->pw_uid, pw->pw_gid);
       else
         printf("n2disk changed user to %s\n", user);
     }
   }
}

/* ******* Crea Graph rddtool *********** */
int creaGraphRrdTool(void)
{
    char graphRrd[1000] = ""; 
    char temp[200] = "";

    sprintf(temp, "rrdtool graph --width 800 --height 400 %s DEF:in1=%s:nICMP:AVERAGE LINE:in1#ff0000:'Pacchetti ICMP' ", pngname, rrdname);
    strcat(graphRrd, temp);

    sprintf(temp, "DEF:in2=%s:nUDP:AVERAGE LINE:in2#00ff00:'Pacchetti UDP' ", rrdname);
    strcat(graphRrd, temp);

    sprintf(temp, "DEF:in3=%s:nTCP:AVERAGE LINE:in3#0000ff:'Pacchetti TCP' ", rrdname);
    strcat(graphRrd, temp);

    //sprintf(temp, "DEF:in4=%s:nICMP:AVERAGE LINE:in3#000000:'Pacchetti ICMP' ", rrdname);
    //strcat(graphRrd, temp);

    system(graphRrd);
    
    return 0;
}

/* ******* Scrittura dati rddtool *********** */
void scritturaRrdTool()
{
    char updateRrd[1000] = ""; 
    char temp[200] = "";

    graph_Number_alarm++;
    sprintf(temp, "rrdtool update %s --template=nICMP:nUDP:nTCP ", rrdname);
    strcat(updateRrd, temp);

    sprintf(temp, "N:%d:%d:%d", num_pckt_icmp, num_pckt_udp, num_pckt_tcp);
    strcat(updateRrd, temp);    

    system(updateRrd);

    /*if(graph_Number_alarm > refreshTime)
    {
       graph_Number_alarm = 0;
       creaGraphRrdTool();
    }*/
    if(creaGraphRrdTool() == -1)
       exit(errno);
    
    printf("---------------------RICERCA FLUSSI DA ELIMINARE---------------------\n");
    refresh(copiaHash, step, time(NULL));
    printf("---------------------------------------------------------------------\n");
          
    sec = alarm(step);//1 step
    //return 0;
}

/* ******* Create rddfile *********** */
int createRrdFile(void)
{
    char createRrd[1000] = ""; 
    char temp[200] = ""; 

    sprintf(temp, "rrdtool create %s --step %d DS:nICMP:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:12:1200 ", rrdname, step, overstep);    
    strcat(createRrd, temp);

    sprintf(temp, "DS:nUDP:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:12:1200 ", overstep);
    strcat(createRrd, temp);

    sprintf(temp, "DS:nTCP:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:12:1200", overstep);
    strcat(createRrd, temp);

    //sprintf(temp, "DS:nICMP:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:12:1200", overstep);
    //strcat(createRrd, temp);

    system(createRrd);
    
    return 0;
}


/* ************** Main ************* */

int main(int argc, char* argv[]) {
  char *in_file = NULL, errbuf[256];
  //char c, *bpf_filter = "udp and ((port 5060) or (port 5061))";
  
  char *dev;

  /* *********** Lista Dispositivi interfacce ****************** */
  dev = pcap_lookupdev(errbuf); //TODO vedere meglio il caso in cui ne ho più di una
  //dev = "eth1";//wmaster0
  if(dev == NULL)
  {
	printf("Can't find default device: %s\n", errbuf);
	return(-1);
  }
  printf("Device: %s\n", dev);  


  in_pcap = pcap_open_live(dev, BUFSIZ, 1, 20, errbuf);

  if(in_pcap == NULL) {
    printf("pcap_open: %s\n", errbuf);
    return(-1);
  }

  changeUser();

/****** TODO Parte filtri da rivedere ******/
/*  if(bpf_filter && (bpf_filter[0] != '\0')) {
    struct bpf_program fcode;

    if((pcap_compile(in_pcap, &fcode, bpf_filter, 1, 0) < 0) || (pcap_setfilter(in_pcap, &fcode) < 0)) {
      printf("Unable to set filter %s. Filter ignored.\n", bpf_filter);
    } else
      printf("Filter '%s' set succesfully\n", bpf_filter);
  }

  if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("socket error: %s\n", strerror(errno));
    return(-1);
  }*/


  datalink = pcap_datalink(in_pcap);

  FILE *rrd = fopen(rrdname, "r");
  
  if(rrd == NULL) 
  {
     if(createRrdFile() == -1)
        return -1;
     else
        printf("Creato file RRD\n");   
  }
  else //TODO Vedi meglio il caso in cui il file esiste già
  {
     printf("File %s già esistente\n", rrdname);
     fclose(rrd);
  }
  
  copiaHash = create_hash(10000);//Crea HashTable

  signal(SIGALRM, scritturaRrdTool);//TODO Vedere meglio warning
  sec = alarm(step);//1 step

  pcap_loop(in_pcap, -1, processPacket, NULL);
  pcap_close(in_pcap);

  printf("Done\n");

  return(0);
}
