/**
 *  @file iodiceSniffer.c
 *  \brief  Implementazione di un semplice packet sniffer.
 *          Lo sniffer salva il flusso di dati catturato in un 
 *          array e in un database rrd (di cui stampa un grafico relativo).
 *          Lo sniffer stampa i seguenti parametri per ogni flusso :
 *	    	- Ip e porta origine (chiave flusso)
 *	    	- Ip e porta destinazione (chiave flusso)
 *		- Numero di pacchetti totali del flusso
 *		- Dimensione totale del flusso
 *		- Timestamp iniziale del flusso
 *		- Timestamp finale del flusso
 *  \author Salvatore Iodice
 */ 

#include <netinet/if_ether.h>
#include "iodiceSniffer.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>

static struct pktFlusso **fluxArr;	/* array di flussi */
static int fluxInd = 0;			/* indice array di flussi */
static int totalTcpPackets = 0;		/* numero totale di pacchetti tcp sniffati */
static int totalUdpPackets = 0;		/* numero totale di pacchetti udp sniffati */
static int which = ITIMER_REAL;		/* parametro per le funzioni di timing */
static sigset_t setAlrm;		/* set globale di segnali SIGALRM */
static sigset_t setTerm;		/* set globale di segnali SIGTERM e SIGINT */
static int sigcount = 0;		/* contatore di segnali catturati */
static int hsize = 0;			/* dimensione header */
static int datalink = 0; 		/* link layer */

static int checkMeno1(int value){

	if(value == -1){
		errno = SIGNALFAIL;
		perror("Si e' verificato un errore!");
		return errno;
	}
	
	return SUCCESS;

}

static int sniffSignals(void){

  	struct sigaction sa1,sa2;

	memset(&sa1,0,sizeof(struct sigaction));
	memset(&sa2,0,sizeof(struct sigaction));

	/* setting di SIGALRM */
	/* svuoto il set di segnali */
     	checkMeno1(sigemptyset(&setAlrm));
	/* aggiungo al set SIGALRM */
	checkMeno1(sigaddset(&setAlrm,SIGALRM));
	/* cambio la maschera dei segnali per il thread gestore
	   aggiungendo I segnali del set */
	checkMeno1(pthread_sigmask(SIG_BLOCK,&setAlrm,NULL));  

    	/* setting di SIGTERM e SIGINT */
	/* svuoto il set di segnali */
     	checkMeno1(sigemptyset(&setTerm));
	/* aggiungo al set SIGTERM */
	checkMeno1(sigaddset(&setTerm,SIGTERM));
	/* e SIGINT */
	checkMeno1(sigaddset(&setTerm,SIGINT));
	/* cambio la maschera dei segnali per il thread gestore
	   aggiungendo I segnali del set */
	checkMeno1(pthread_sigmask(SIG_BLOCK,&setTerm,NULL));  

	return SUCCESS;

}

/**
   Gestore del segnale SIGALRM
*/
void* sniffHandleALRM(void *arg){

	char rrdStr[MAXLEN];			/* stringa per aggiornare il contatore */
	int value = 0;				/* segnale ricevuto */
	int i;

    	while(sigcount>=0){
		/*  sospendo il thread handler finche' non arriva un segnale di SIGALRM */
		sigwait(&setAlrm,&value);
    		sigcount++;

	  	/* aggiorno i contatori nel database */
	 	snprintf(rrdStr,MAXLEN,"rrdtool update iodiceSniffer.rrd \
			 N:%d:%d",totalTcpPackets,totalUdpPackets);

		system(rrdStr);

		/* opzioni : larghezza 500, max value 500 */
		system("rrdtool graph iodiceSniffer.png -t iodiceSniffer -s end-1hours -w 500 \
			DEF:n1=iodiceSniffer.rrd:totalTcpPackets:AVERAGE LINE:n1#CC0000:'Numero Pacchetti Tcp'\
			DEF:n2=iodiceSniffer.rrd:totalUdpPackets:AVERAGE LINE:n2#CCFF00:'Numero Pacchetti Udp'\
			>/dev/null");

		for(i=0;i<fluxInd;i++){
			printf(SPATIATOR);
			printf("				Flusso #%d Catturato				\n",i);
			printf("Src IP: %s, src port: %d -> Dest IP: %s, dest port: %d \n"\
				,FLUXARR->srcIp,FLUXARR->srcPort,FLUXARR->dstIp,FLUXARR->dstPort);
			printf("#Pacchetti flusso: %d Dimensione flusso: %d \n"\
				,FLUXARR->totalPkts,FLUXARR->totalSize); 
			printf("Timestamp iniziale: %s -> Timestamp finale: %s\n"\
				,FLUXARR->strInittime,FLUXARR->strFinaltime); 
			printf(SPATIATOR);
		}

	}

  	exit(EXIT_FAILURE);

}

/**
   Gestore del segnale SIGTERM e SIGINT
   Stampa a video tutti i flussi, libera la memoria e termina.
*/
void* sniffHandleTERM(void *arg){

	int value = 0;				/* segnale ricevuto */
	int i = 0;

	/*  sospendo il thread handler finche' non arriva un segnale di SIGALRM */
	sigwait(&setTerm,&value);
    	
	system("clear");
	printf(">>>> Il sistema sta terminando !! <<<<\n");
	printf(">>>> Visualizzazione dei flussi catturati <<<<\n");
	for(i=0;i<fluxInd;i++){
		printf(SPATIATOR);
		printf("				Flusso #%d Catturato				\n",i);
		printf("Src IP: %s, src port: %d -> Dest IP: %s, dest port: %d \n"\
			,FLUXARR->srcIp,FLUXARR->srcPort,FLUXARR->dstIp,FLUXARR->dstPort);
		printf("#Pacchetti flusso: %d Dimensione flusso: %d \n"\
			,FLUXARR->totalPkts,FLUXARR->totalSize); 
		printf("Timestamp iniziale: %s -> Timestamp finale: %s\n"\
			,FLUXARR->strInittime,FLUXARR->strFinaltime); 
		printf(SPATIATOR);
	}

	/* libero tutti i flussi */
	deleteFlux();

	exit(EXIT_SUCCESS);

}

/**
   Funzione callback per il loop
	args : ultimo argomento della pcap_loop()
	header : header del pacchetto contenente tutte le info
	pkt : il pacchetto sniffato
*/
void snifferHandler(u_char* args,const struct pcap_pkthdr* header,const u_char* pkt){

	int hlen = hsize;			/* offeset headers */
	char* ipsrc,* ipdest;			/* ip sorgente e destinazione */
	uint16_t src,dest;   			/* porta sorgente e destinazione */
	struct ip* ip;				/* struttura header ip */
	struct tcphdr* tcph;			/* struttura header tcp */
	struct udphdr* udph;			/* struttura header udp */
	struct timeval ts = header->ts;		/* timestamp */
 	struct tm* time;			/* struct per convertire il ts */
	char strtime[MAXLEN];			/* stringa per rappresentare il ts */

	/* mi posiziono sull'header ip */
	ip = (struct ip *)(pkt + hlen);

	if(!(ipsrc = malloc(INET_ADDRSTRLEN*sizeof(char)))){
		errno = ENOMEM;
		perror("Allocazione non riuscita");
		return;
	}
	if(!(ipdest = malloc(INET_ADDRSTRLEN*sizeof(char)))){
		errno = ENOMEM;
		perror("Allocazione non riuscita");
		return;
	}
	/* converto gli indirizzi ip in formato stringa */
   	inet_ntop(AF_INET,&ip->ip_src,ipsrc,INET_ADDRSTRLEN);
    	inet_ntop(AF_INET,&ip->ip_dst,ipdest,INET_ADDRSTRLEN);

  	hlen += ((u_int)ip->ip_hl * 4);

	/* caso tcp */
	if (ip->ip_p == 6){  	
		/* mi posiziono sull'header tcp */		
       		tcph = (struct tcphdr*)(pkt + hlen);
        	src = ntohs(tcph->source);
        	dest = ntohs(tcph->dest);
		totalTcpPackets++;
	} 
	/* caso udp */
	else if (ip->ip_p == 17){
		/* mi posiziono sull'header udp */
		udph = (struct udphdr*)(pkt + hlen);
      	 	src = ntohs(udph->source);
        	dest = ntohs(udph->dest);
		totalUdpPackets++;
	}

  	/* Formatto il timestamp con formato : "Giorno aaa-mm-gg hh:mm:ss Zona" */
	time = localtime(&ts.tv_sec);
	strftime(strtime,sizeof(strtime),"%a %Y-%m-%d %H:%M:%S %Z",time);

	/* aggiorno i flussi dell'array */
	createFlux(src,ipsrc,dest,ipdest,1,header->len,strtime,strtime);

}

static void createFlux(int srcPort,char* srcIp,int dstPort,char* dstIp,int totalPkts,
		       int totalSize,char strInittime[],char strFinaltime[]){

	/* indice per scorrere l'array */
	int ind = fluxInd;

	/* controllo in quale flusso mettere il pacchetto */
	while (ind > 0 && ind < MAXARR){
		/* se individuo un flusso */
		if(FINAL_CHECK){
			/* aggiorno i campi... */
			fluxArr[ind-1]->totalPkts++;
			fluxArr[ind-1]->totalSize += totalSize;
			strncpy(fluxArr[ind-1]->strFinaltime,strFinaltime,MAXLEN);
			break;
		}
		else ind--;
	}
	/* ...altrimenti devo creare un nuovo flusso */
	if(ind == 0){
		struct pktFlusso* p;
		if(!(p = (void*)calloc(1,sizeof(struct pktFlusso)))){
			errno = ENOMEM;
			perror("Allocazione non riuscita!");
		}
		p->srcPort=srcPort;
		p->srcIp=srcIp;
		p->dstPort=dstPort;
		p->dstIp=dstIp;
		p->totalPkts=totalPkts;
		p->totalSize=totalSize;
		strncpy(p->strInittime,strInittime,MAXLEN);
		strncpy(p->strFinaltime,strFinaltime,MAXLEN);
		fluxArr[fluxInd] = p;
		fluxInd++;
	}
	
}

static void deleteFlux(){

	int i = 0;

	/* libero i singoli flussi */
	for(i=0;i<fluxInd;i++)	free(fluxArr[i]);
	/* e l'array */	
	free(fluxArr);

}

int main( int argc, char *argv[] ) {

    	struct itimerval value, ovalue, pvalue;		/* strutture timer per le funzioni di timing */
    	char errbuf[PCAP_ERRBUF_SIZE]; 			/* buffer errori */
	pcap_t* psession = NULL;			/* sessione pcap corrente */
	pcap_if_t* alldevsp,* alldevspt;		/* struttura per salvare i devices */
  	char devname[5];				/* device da cui sniffare */
	pcap_handler handler = &snifferHandler; 	/* handler del loop */
	pthread_t handlerALRM;				/* identificatore thread handler SIGALRM */
	pthread_t handlerTERM;				/* identificatore thread handler SIGTERM e SIGINT */

	/* attivo la gestione dei segnali */
	sniffSignals();

	/* alloco memoria per l'array di strutture */
	fluxArr = calloc(1,MAXARR*sizeof(struct pktFlusso*));
	if(fluxArr==NULL) {
		errno = ENOMEM;
		perror("Allocazione array non riuscita");
		return FAIL;
	}

   	getitimer(which,&pvalue);

	/* Setto l'intervallo per ripetersi ogni 60 secondi */
	value.it_interval.tv_sec = 60;        
	value.it_interval.tv_usec = 0;
    	value.it_value.tv_sec = 60;
    	value.it_value.tv_usec = 0;

	/* individuo e seleziono i devices usabili */
   	if(!pcap_findalldevs(&alldevsp,errbuf)){
		alldevspt=alldevsp;
        	while(alldevspt){
              		printf("Devices usabili : %s\n",alldevspt->name);
           		alldevspt=alldevspt->next;
                }
        }
              
	/* creo il thread handler di SIGALRM */
	if(pthread_create(&handlerALRM,NULL,&sniffHandleALRM,NULL)!=0){
		perror("Errore nella creazione thread handler SIGALRM");
		return FAIL;
	}

	/* creo il thread handler di SIGTERM e SIGINT */
	if(pthread_create(&handlerTERM,NULL,&sniffHandleTERM,NULL)!=0){
		perror("Errore nella creazione thread handler SIGTERM e SIGINT");
		return FAIL;
	}

  	printf("Seleziona il device : ");
   	scanf("%s",devname);

	/* faccio partire il timer */
   	setitimer(which,&value,&ovalue);

	if(!(psession = pcap_open_live(devname,65535,1,1500,errbuf))){ 
		fprintf(stderr,"Errore: impossibile aprire il device : %s\n",errbuf);		
		return FAIL; 
	}

	/* prendo il tipo del link layer */
 	datalink = pcap_datalink(psession);
	/* prendo la dimensione dell'header */
	switch(datalink){
		case DLT_LINUX_SLL:
        	hsize = 16;
        	break;

		case DLT_EN10MB:
		hsize = sizeof(struct ether_header);
	        break;

		case DLT_IEEE802_11:
	        hsize = 12;
        	break;

    		default:
        	return FAIL;
	}
	
	/* creo il database rrd per lo sniffer */
	/* parametri : ogni 60 secondi (step) , falso dopo 100, minimo 0 , massimo 5000 */
	system("rrdtool create iodiceSniffer.rrd --step=60 \
		DS:totalTcpPackets:COUNTER:100:0:5000 RRA:AVERAGE:0.5:1:200 \
		DS:totalUdpPackets:COUNTER:100:0:5000 RRA:AVERAGE:0.5:1:200");

	/* inizio a sniffare fino a che non c'e' un errore */
	if(pcap_loop(psession,-1,handler,NULL)==-1){
		pcap_perror(psession,"Errore nel loop di cattura");
		return FAIL;
	}

	if(pthread_join(handlerALRM,NULL)!=0){
		perror("Errore nella join dell'handler SIGALRM");
		return FAIL;
	}

	if(pthread_join(handlerTERM,NULL)!=0){
		perror("Errore nella join dell'handler SIGTERM e SIGINT");
		return FAIL;
	}

  	pcap_close(psession);

    return SUCCESS;

}

