/*
*	alessioCastiSniffer.c: prova d'uso di LPCAP
*	Autore: Alessio Casti
*	
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include "libflussi.h"

#define IFERROR(s,m) if((s)==-1) {perror(m); exit(errno);}

#define NPak 5
#define COLS 16
#define MaxPak 20


void help();
void termina();
void update();
void *thread_operatore(void  *num_coda);
void *thread_cleaner(void *tabellaHash);

pcap_if_t *lista_periferiche, *p; //lista interfaccie attive
pcap_t *periferica; //interfaccia

int uid=1;
extern int errno;
unsigned long int n_pak_tcp=0; //pacchetti TCP ricevuti
unsigned long int n_pak_udp=0; //pacchetti UDP ricevuti

int dump=0;

		
	//STRUTTURE DATI PER GESTIRE IL FLUSSO
	
	
	int retcode;
		
	struct sigaction terminazione; //per richiesta terminazione
 	struct sigaction interruzione; //per richiesta terminazione da tastiera CTRL+C
 	struct sigaction segfault; //terminazione da segmentation fault
	struct sigaction alarmDump; //timer rrdtool update
	

main (int argc, char **argv)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *a; //puntatore struttura lista indirizzi associati alla interfaccia
	const u_char *packet; //pacchetto catturato	
	struct pcap_pkthdr *header; //header pacchetto catturato
	struct sockaddr_in *add; //ptr alla struttura contenente indirizzi dell'interfaccia di rete
	struct bpf_program filtro; //risultato compilazione filtri pacchetto
	struct ether_header * ether_type; //variabile che conterrà il tipo di pacchetto ethernet
	int off_data; //offset payload per il pacchetto datalink
	const int off_ip_src=12; //offset campo IP mittente pacchetto IPV4
	const int off_ip_dest=16; //offset campo IP destinatario pacchetto IPV4
	const int off_port_dest=2; //offset campo porta destinatario protocolli TCP|UDP
	const int off_port_src=0; //offset campo porta mittente protocolli TCP|UDP
	
	const int off_ether_type=20; //offset campo ethernet_type ETHERNET
	
	int lung_header_ip; //lunghezza header IPV4 (calcolata)
	int argomenti; 
	int c;
	short maschera=15; //00001111, usata per estrapolare la parte bassa di un byte
	int link_layer; //tipo link [implementato: ethernet e 802.11]
	int i=0;
	int j=0;
	int num_interfaccia_sel=0;
	int protocollo; //protocollo pacchetto
	unsigned long int n_pak=0; //pacchetti ricevuti
	int npack=MaxPak;	
	int res=0;
	int stampa_porte=0;
	int contenuto=0;
	int promiscuo=0;

	char tmp[20]="";


	int loop=0;
	
	time_t t;
	struct tm * timeinfo;
	char timeDate[30];
	int retcode; //usato per ricevere codice terminazione dai thread del flusso
	struct in_addr mittente;
	struct in_addr destinatario;
	const char mitt[15];
	const char dest[15];
	unsigned short int portamittente;
	unsigned short int portadestinatario;
	int indexCoda;	
	int endCoda;
	elemento_coda el_tmp;
	
//INIZIO
	
	system("clear");
	uid=geteuid();
	printf("\nUID: %d\n",uid);
	if(uid!=0)
	{	
		printf("\n# Devi essere root per aprire le interfacce di rete: esco\n");
		exit(1);
	
	}
	
	//INIZIALIZZO STRUTTURE DATI
	
	for(i=0; i<NumThreadProbe; i++)
	{
		q[i].inizio=0;
		q[i].fine=-1;
		q[i].size=0;
		signalTermThread[i]=1;
		pthread_mutex_init(&mutex[i],NULL);		
	}
	
	signalTermThread[i]=1;	
		
	
	fsc.inizio=0;
	fsc.fine=-1;
	fsc.size=0;
	
	for(i=0; i<DimHash; i++)
	{
		HashTable[i]=NULL;
	}
	
	int num_coda=0;
	
	
	if(argc>0)
	{
		while ((argomenti = getopt(argc, argv, "n:cplfdh")) != -1)
		{
			switch (argomenti)
			{
				case 'n':
					npack = atoi(optarg); //numero pacchetti da analizzare (default:20)
				break;
				
				case 'c':
					contenuto=1; //stampa contenuto pacchetti
				break;
				
				case 'p':
					promiscuo=1; //stampa contenuto pacchetti
				break;
				
				case 'l':
					loop=1; //looppa
				break;
				
				case 'd':
					dump=1;  //fa il dump della cattura su alessioCastiCaptured.rrd
				break;
				
				default:
					help(); //stampa help
				break;
			}
		}
	}
	
	//customizzo il comportamento di sigaction nel caso in cui alessioCastiSniffer riceva un segnale di interruzione
                                     
 	terminazione.sa_handler=termina; 
	
	interruzione.sa_handler=termina;
	
    segfault.sa_handler=termina; 
                 
	alarmDump.sa_handler=update;
	
	//sa_handler specifica l'azione che sara' associata nel caso in cui venga ricevuto il segnale SIGINT o SIGTERM
	IFERROR(sigaction(SIGINT,&interruzione,NULL),"\n# alessioCastiSniffer: errore nella gestione della terminazione da tastiera\n");
	IFERROR(sigaction(SIGTERM,&terminazione,NULL),"\n# alessioCastiSniffer: errore nella gestione della terminazione\n");
	IFERROR(sigaction(SIGSEGV,&segfault,NULL),"\n# alessioCastiSniffer: errore nella gestione di Segmentation Fault\n");
	IFERROR(sigaction(SIGALRM,&alarmDump,NULL),"\n# alessioCastiSniffer: errore nella gestione di SIGALRM x rrdupdate\n");

	
	printf("#### PROVA D'USO DI LIBPCAP ####\n\n",npack);	
	
		
	//INFORMO QUANTI THREAD VOGLIO LANCIARE
	
	
	if(pthread_setconcurrency(NumThreadProbe+2)!=0)
	{
		printf ("\n# Errore nella creazione dei Thread.\n\n");
		exit (1);
	} 
	
	//CREO I THREAD PER GESTIRE I FLUSSI
	
	
	for(i=0;i<NumThreadProbe;i++)
	{
		printf("# Cerco di creare Thread Operatore %d: ",i+1);
		if (pthread_create(&threadOperatori[i], NULL, thread_operatore,(void *) i)!=0)
		{ 
			printf ("\n# Errore nella creazione del Thread Operatore %d.\n\n",i+1);
	  		exit (1);
		}
		printf("OK\n");
	}
	
	printf("\n# Cerco di creare Thread Cleaner: ");
	if (pthread_create(&cleaner, NULL, thread_cleaner, HashTable)!=0)
	{ 
		printf ("\n# Errore nella creazione del Thread Cleaner.\n\n");
  		exit (1);
	}
	printf("OK\n");
	
	if(dump)
	{
		//faccio il dump con rrdtool
		printf("# Modalità Dump rilevata.\n\n");
		//controllo se esiste il file rrd
		if(myfileExist("alessioCastiCaptured.rrd")==0)
		{
			printf("# Cerco di creare alessioCastiCaptured.rrd perchè non esiste: ");
			IFERROR(system("rrdtool create alessioCastiCaptured.rrd --step=60 DS:npakUDP:COUNTER:70:0:7000 RRA:AVERAGE:0.5:1:120 DS:npakTCP:COUNTER:70:0:7000 RRA:AVERAGE:0.5:1:120"),"\n# Errore nell'invocazione di rrdtool create\n");
			 printf("OK.\n\n");
		}
		printf("# rrdtool info:\n\n");
		system("rrdtool info alessioCastiCaptured.rrd");
		
	}
	// Se non sono root, setto i privilegi di root
	if (uid)
  		setuid(0);
  
  	//cerco le interfacce di rete
	if (pcap_findalldevs(&lista_periferiche, errbuf) == -1)
        {
            	printf ("\n# Errore in pcap_findalldevs() %s\n",errbuf);
				// Torno a settare i permessi di utente normale
				if (uid>0)
		  			setuid(uid);
				exit(1);
		}
		
	// Torno a settare i permessi di utente normale
	if (uid>0)alarm(60);
		setuid(uid);
	
	do
	{	
		//elenco le interfacce di rete
		printf("\n#### INTERFACCE RILEVATE ####\n\n");		
		i=0;
		for(p=lista_periferiche; p; p=p->next)
		{
			printf("%d. %s", ++i, p->name);
			if (p->description)
				printf(" (%s) ", p->description);
			else
				printf(" (N/P) ");
								
			if(p->addresses)
			{	
				for(a=(p->addresses); a; a=a->next)
				{
					//NON RIESCO AD ACCEDERE ALLA STRUTTURA CONTENENTE GLI INDIRIZZI ASSOCIATI ALLA INTERFACCIA CORRENTE					
					//add = (struct sockaddr_in *) a->addr;
					//printf("- [%d] ", inet_ntoa(add->sin_addr.s_addr));
					
				}
				printf("\n");
			}
			else
			{
				printf("\n");
			}
		}

		if(i==0)
		{
		    printf("\n# Nessuna interfaccia rilevata!\n");
		    exit(1);
		}
		printf("\n> inserisci il numero di interfaccia da usare (1-%d, 0=EXIT): ",i);
    	scanf("%d", & num_interfaccia_sel);
	}
	while( num_interfaccia_sel<0 ||  num_interfaccia_sel>i);
	if(num_interfaccia_sel==0)
	{
		pcap_freealldevs(lista_periferiche);	
		exit(0);
	}	
	printf("\n# Selezionata interfaccia %d.\n", num_interfaccia_sel);
	
	//cerco di aprire l'interfaccia
	printf("\n# Cerco di aprire l'interfaccia %d...\n", num_interfaccia_sel);

	//seleziono l'interfaccia
	for(p=lista_periferiche, i=1; i< num_interfaccia_sel; p=p->next, i++);

	uid=geteuid();
 	IFERROR(sigaction(SIGINT,&interruzione,NULL),"\n# alessioCastiSniffer: errore nella gestione della terminazione da tastiera\n");
	// Se non sono root, setto i privilegi di root
	if (uid)
  		setuid(0);

	
	if ( (periferica= pcap_open_live(p->name, 1024, promiscuo, 20, errbuf) ) == NULL)
    {
		printf("\n# Errore nell'apertura dell'interfaccia %s\n",p->name);
		pcap_freealldevs(lista_periferiche);	
		// Torno a settare i permessi di utente normale
		if (uid>0)
  			setuid(uid);
		exit(1);
		
    }
	
	// Torno a settare i permessi di utente normale
	if (uid>0)
 		setuid(uid);
	printf("\n# Aperta interfaccia %s.\n", p->name);
	
	//INDIVIDUO LINK LAYER
	link_layer = pcap_datalink(periferica);
	
	switch (link_layer)
	{
		case DLT_EN10MB: // Ethernet II
			off_data = 14;
			printf("\n# Link = Ethernet (%d).\n", DLT_EN10MB);
		break;
		
		case DLT_IEEE802_11: // Wi-fi 802.11
			off_data = 20;
			printf("\n# Link = Wi-fi 802.11 (%d).\n",DLT_IEEE802_11);
			break;
		
		default:
			printf("\n# Link fisico [%d] non supportato, connettere con Ethernet o 802.11 (Wi-fi).\n", link_layer);
			exit(1);
		break;
	}

	alarm(60);

	while((((res = pcap_next_ex(periferica, &header, &packet)) >= 0) && (n_pak < npack))|| loop)
	{
		stampa_porte=0;
				
		if(res==0)
		{
			//printf("\n# TIMEOUT\n");
			continue;
		}	
		
				
		ether_type = (struct ether_header *) packet;

		if (ntohs (ether_type->ether_type) == ETHERTYPE_IP)
		{
			//lunghezza header IP
			c = maschera & packet[off_data];
			lung_header_ip=c*4; //byte in cui inizia il segmento data dell'IPV4 [(ultimi 4 bit del primo byte dell'header IPV4 che individuano la lun in parole) * lunghezza parola/8 bit] 
			//printf("\n BYTE FINE HEADER: %d ",lung_header_ip);
			
			//controllo se il pacchetto non è spezzato o il datagramma IP			
			if(((bpf_u_int32) header->caplen !=(bpf_u_int32) header->len)||(header->caplen < (lung_header_ip+4)))
			{
				printf("\n PACCHETTO IGNORATO PERCHE' SPEZZATO\n");
				continue;
			}
			n_pak++;	
			printf("_________________________________________________________________");
			printf("\nPACCHETTO %ld \n\n",n_pak);	
			printf(" ETHERNET TYPE: IP\n");
			printf(" TIMESTAMP: %ld.%ld \n", header->ts.tv_sec,header->ts.tv_usec);
			printf(" LUNGHEZZA PACCHETTO: %ld byte",(bpf_u_int32) header->len);
			if(contenuto)
			{
				printf("\n CONTENUTO PACCHETTO:");

				for(j=0; (j <= header->caplen); j++)
				{
					if((j%16) == 0)
					{
						printf("\n\t\t ");	
					}
					printf("%.2x ", packet[j]);
				}
				printf("\n");
				
			}		
				
			//controllo protocollo payload ethernet
			protocollo = packet[off_data+9]; //punto al byte che specifica il protocollo
			switch(protocollo)
			{
				case 1:
					printf("\n PROTOCOLLO: ICMP (1)");
								
				break;
		
				case 3:
					printf("\n PROTOCOLLO: Gateway-to-Gateway (3)");
				break;
		
				case 4:
					printf("\n PROTOCOLLO: CMCC Gateway Monitoring Message (4)");
				break;
		
				case 5:
					printf("\n PROTOCOLLO: ST (5)");
				break;
		
				case 6:
					printf("\n PROTOCOLLO: TCP (6)");
					stampa_porte=1;
					if(dump)
						n_pak_tcp++;
				break;
		
				case 7:
					printf("\n PROTOCOLLO: UCL (7)");
				break;
		
				case 9:
					printf("\n PROTOCOLLO: Secure (9)");
				break;
		
				case 10:
					printf("\n PROTOCOLLO: BBN RCC Monitoring (10)");
				break;
		
				case 11:
					printf("\n PROTOCOLLO: NVP (11)");
				break;
		
				case 12:
					printf("\n PROTOCOLLO: PUP (12)");
				break;
		
				case 13:
					printf("\n PROTOCOLLO: Pluribus (13)");
				break;
		
				case 14:
					printf("\n PROTOCOLLO: Telenet (14)");
				break;
		
				case 15:
					printf("\n PROTOCOLLO: XNET (15)");
				break;
		
				case 16:
					printf("\n PROTOCOLLO: Chaos (16)");
				break;
		
				case 17:
					printf("\n PROTOCOLLO: UDP (17)");
					stampa_porte=1;
					if(dump)
						n_pak_udp++;
				break;
		
				case 18:
					printf("\n PROTOCOLLO: Multiplexing (18)");
				break;
		
				case 19:
					printf("\n PROTOCOLLO: DCN (19)");
				break;
		
				case 20:
					printf("\n PROTOCOLLO: TAC Monitoring (20)");
				break;
		
				case 64:
					printf("\n PROTOCOLLO: SATNET and Backroom EXPAK (64)");
				break;
		
				case 65:
					printf("\n PROTOCOLLO: MIT Subnet Support (65)");
		
				case 69:
					printf("\n PROTOCOLLO: SATNET Monitoring (69)");
				break;
		
				case 71:
					printf("\n PROTOCOLLO: Internet Packet Core Utility (71)");
				break;
		
				case 76:
					printf("\n PROTOCOLLO: SATNET and Backroom EXPAK (76)");
				break;
		
				case 78:
					printf("\n PROTOCOLLO: SWIDEBAND Monitoring (78)");
				break;
		
				case 79:
					printf("\n PROTOCOLLO: WIDEBAND EXPAK (79)");
				break;
		
				default:
					printf("\n PROTOCOLLO: N/P (%d)", protocollo);					
				break;
			}
	
			
	
	
			//IP sorgente: 4 byte a partire da off_data+off_ip_src
			//porta sorgente: 2byte a partire da off_data+off_port_src+lung_header_ip;
			//IP destinatario: 4 byte a partire da off_data+off_ip_dest
			//porta destinazione: 2 byte a partire da off_data+off_port_dest+lung_header_ip
			
			memcpy(&mittente, packet + off_data+off_ip_src, sizeof(struct in_addr));
			memcpy(&destinatario, packet + off_data+off_ip_dest, sizeof(struct in_addr));
			
			sprintf(mitt, (char *) inet_ntoa(mittente),"%s");
			sprintf(dest, (char *) inet_ntoa(destinatario),"%s");
			
			
			if(stampa_porte) //se il protocollo è TCP|UDP stampa anche le porte del mittente e del destinatario
			{
				portamittente=packet[off_data+off_port_src+lung_header_ip]*256+packet[off_data+off_port_src+lung_header_ip+1];
				portadestinatario=packet[off_data+off_port_dest+lung_header_ip]*256+packet[off_data+off_port_dest+lung_header_ip+1];
								
				printf("\n MITTENTE: %s:%d", mitt, portamittente);
				
				printf("\n DESTINATARIO: %s:%d", dest, portadestinatario);
				//CALCOLO HASH CODA
				indexCoda=hashCoda(mittente.s_addr+destinatario.s_addr+portamittente+portadestinatario);
				
				//aggiorno l'ultimissimo timestamp
				
				if((header->ts).tv_sec>lastest.sec)
					if((header->ts).tv_usec>lastest.msec)
					{
						lastest.sec=header->ts.tv_sec;
						lastest.msec=header->ts.tv_usec;				
					}
				//pthread_mutex_lock(&mutex[indexCoda]);
				//if(q[indexCoda].size < DimCoda)				
				//{
				
					//aggiorno indici gestione coda
					
					
					//q[indexCcondition_toda].size++;
					
					//q[indexCoda].fine=(q[indexCoda].fine+1)%DimCoda;
				
					//endCoda=q[indexCoda].fine;
				
					//copio dati pacchetto dentro struttura coda
					
					el_tmp.caplen=header->caplen;
					//q[indexCoda].coda[endCoda].caplen=header->caplen;
					
					el_tmp.ts.sec=header->ts.tv_sec;
					//q[indexCoda].coda[endCoda].ts.sec=header->ts.tv_sec;
					//printf("\n\tcopiato sec: %ld\n",q[indexCoda].coda[endCoda].ts.sec);
				
					el_tmp.ts.msec=header->ts.tv_usec;
					//q[indexCoda].coda[endCoda].ts.msec=header->ts.tv_usec;
					//printf("\n\tcopiato msec: %ld\n",q[indexCoda].coda[endCoda].ts.msec);
				
					el_tmp.mittente.s_addr=mittente.s_addr;
					//q[indexCoda].coda[endCoda].mittente.s_addr=mittente.s_addr;
					//printf("\n\tcopiato mitt: %s\n", (char *) inet_ntoa(q[indexCoda].coda[endCoda].mittente));
				
					el_tmp.destinatario.s_addr=destinatario.s_addr;
					//q[indexCoda].coda[endCoda].destinatario.s_addr=destinatario.s_addr;
					//printf("\n\tcopiato dest: %s\n", (char *) inet_ntoa(q[indexCoda].coda[endCoda].destinatario));
				
					strcpy(el_tmp.mitt,mitt);
					//strcpy(q[indexCoda].coda[endCoda].mitt,mitt);
					//printf("\n\tcopiato mitt stringa: %s\n",q[indexCoda].coda[endCoda].mitt);
				
					strcpy(el_tmp.dest,dest);
					//strcpy(q[indexCoda].coda[endCoda].dest,dest);
					//printf("\n\tcopiato dest stringa: %s\n",q[indexCoda].coda[endCoda].dest);
				
					el_tmp.mitt_port=portamittente;
					//q[indexCoda].coda[endCoda].mitt_port=portamittente;
					//printf("\n\tcopiato porta mitt: %d\n",q[indexCoda].coda[endCoda].mitt_port);
				
					el_tmp.dest_port=portadestinatario;
					//q[indexCoda].coda[endCoda].dest_port=portadestinatario;
					//printf("\n\tcopiato porta dest: %d\n",q[indexCoda].coda[endCoda].dest_port);
					
					if(enqueue(&el_tmp, indexCoda)<=0)
						printf("\n# Main: pacchetto scartato perchè coda %d è piena: %d\n",indexCoda,q[indexCoda].size);
				//}
					/*
					else
						printf("\n# Main: pacchetto inserito in coda %d capacità %d inizio: %d fine: %d\n",indexCoda,q[indexCoda].size,q[indexCoda].inizio,q[indexCoda].fine);
						*/
				
				//pthread_mutex_unlock(&mutex[indexCoda]);
				
			}
			else
			{			
				printf("\n MITTENTE: %s", mitt);
				printf("\n DESTINATARIO: %s", dest);
			}
			printf("\n_________________________________________________________________\n\n");   
		}
		else  if (ntohs (ether_type->ether_type) == ETHERTYPE_ARP)
		{
			printf("\n# Ethernet type (hex:%x dec:%d) = Pacchetto ARP: IGNORATO\n", ntohs(ether_type->ether_type), ntohs(ether_type->ether_type));
		}
		else 
		{
			printf("\n# Ethernet type %x: IGNORATO.", ntohs(ether_type->ether_type));
		}
	}

	// rilascio le interfacce
	printf("\n# Rilascio le interfacce: ");
	pcap_freealldevs(lista_periferiche);
	pcap_close(periferica);
	printf("OK\n");
		
	if(dump)
	{
		printf("\n# Genero Grafico con rrdtool: ");
		IFERROR(system("rrdtool graph --start=end-10m alessioCastiCaptured.png DEF:in1=alessioCastiCaptured.rrd:npakTCP:AVERAGE LINE:in1#ff0000:'Pacchetti TCP' DEF:in2=alessioCastiCaptured.rrd:npakUDP:AVERAGE LINE:in2#0000ff:'Pacchetti UDP'"),"\n# Errore nell'invocazione di rrdtool graph.\n");
		printf("OK\n");
	}
	exit(0);
}

//stampa l'help del programma
void help()
{
	printf("\n###########################################################################\n");
	printf("\nalessioCastiSniffer: prova d'uso LPCAP\n");
	printf("\nAutore: Alessio Casti");
	printf("\n\n\tPARAMETRI ");
	printf("\n\t\t -n numero       : specifica quanti pacchetti analizzare");
	printf("\n\t\t -p              : abilita la modalità promiscua");
	printf("\n\t\t -c              : stampa il contenuto del pacchetto");
	printf("\n\t\t -l              : cattura finchè non si preme ctrl+c");
	printf("\n\t\t -d              : esegue il dump dei pacchetti con rrdtool [#pacchetti TCP ogni 60 sec, #pacchetti UDP ogni 60 sec]");
	printf("\n\t\t -h              : questa guida\n");
	printf("\n###########################################################################\n\n");
	exit(0);
}

//gestisce la terminazione del programma
void termina()
{
	int ok=1;
	int i=0;
	printf("\n\n# Main: ricevuto segnale di terminazione o intercettato Segmentation Fault: salvataggio dati... \n");
	printf("\n# Rilascio le interfacce: ");
	if(lista_periferiche)
		pcap_freealldevs(lista_periferiche);
	
	if(periferica)
		pcap_close(periferica);
		
	printf("OK\n");
		
	if(dump)
	{
		printf("\n# Genero Grafico con rrdtool: ");
		IFERROR(system("rrdtool graph --start=end-10m alessioCastiCaptured.png DEF:in1=alessioCastiCaptured.rrd:npakTCP:AVERAGE LINE:in1#ff0000:'Pacchetti TCP' DEF:in2=alessioCastiCaptured.rrd:npakUDP:AVERAGE LINE:in2#0000ff:'Pacchetti UDP'"),"\n# Errore nell'invocazione di rrdtool graph.\n");
		printf("OK\n");
	}
	
	// Torno a settare i permessi di utente normale
	if (uid>0)
 		setuid(uid);
 	
 	
 	//attendo terminazione thread
	
	for(i=0;i<NumThreadProbe;i++)
	{
		printf("\n# Attendo terminazione Thread Operatore %d: ",i+1);
		signalTermThread[i]=0;
		retcode = pthread_join(threadOperatori[i], NULL);
		if (retcode != 0)
	  	{
	  		printf ("\n\tjoin() sul Thread Operatore %d fallita: %d\n", i+1, retcode);			
		}
		printf("OK\n");
	}
	
	signalTermThread[NumThreadProbe]=0;
	pthread_mutex_lock(&mutex_goCleaner);
	goCleaner=1;
	pthread_cond_signal(&cond_goCleaner);
	pthread_mutex_unlock(&mutex_goCleaner);
	
	printf("\n# Attendo terminazione Thread Cleaner: ");
	retcode = pthread_join(cleaner, NULL);
  	if (retcode != 0)
  	{
  		printf ("\n\tjoin() sul Thread Cleaner fallita: %d\n", retcode);
	}
	printf("OK\n");
	
	printf("\n...esco!\n\n");
	exit(1);
}

void update()
{
	if(dump)
	{
		printf("\n# Eseguo rrdtool update: ");
		char udp[30];
		char tcp[30];
		char cmd[500]="rrdtool update alessioCastiCaptured.rrd --template=npakUDP:npakTCP N:";
		printf("\nrrdtool update alessioCastiCaptured.rrd --template=npakUDP:npakTCP N:%ld:%ld\n\n",n_pak_udp,n_pak_tcp);
		sprintf(udp,"%ld",n_pak_udp);
		sprintf(tcp,"%ld",n_pak_tcp);
		strcat(cmd,udp);
		strcat(cmd,":");
		strcat(cmd,tcp);
		IFERROR(system(cmd),"\n# Errore nell'invocazione di rrdtool update.\n");
		printf("OK.\n");	
	}
	
	alarm(60);

	//thread Cleaner
	pthread_mutex_lock(&mutex_goCleaner);
	goCleaner=1;
	pthread_cond_signal(&cond_goCleaner);
	pthread_mutex_unlock(&mutex_goCleaner);	
}

//resituisce true se filename esiste
int myfileExist(char * filename)
{
	
    if(strlen(filename)<=0)
    {
    	//printf("\n# myfileExist: inserire nome file\n");
    	return(0);   //  No filename = no file.

	}
	//printf("\n# myfileExist: cerco di aprire il file: ");
	FILE *f=fopen(filename,"r");
	//printf("OK.\n");
    if(f)
    {   //  Chiamata riuscita... Il file esiste.
        fclose(f);
		return(1);
    }

    return(0);
}

//gestisce il comportamento del Thread che si occupa di modificare i bucket del flusso
void *thread_operatore(void * num_coda)
{
	elemento_coda *el;
	int ncoda;
	ncoda=(int) num_coda;
	int ret;
	while(signalTermThread[ncoda])
	{
		if((el=(elemento_coda *) dequeue(ncoda))!=NULL) //coda associata al Thread non vuota
		{
			if(elaboraFlusso(el)==0)
				printf("\n# Thread Operatore pacchetto non gestito\n");
		}
	}
	pthread_exit(0);
}


//gestisce il comportamento del Thread che si occupa di controllare i flussi scaduti
void *thread_cleaner(void *arg)
{
	int j=0;
	int cont;
	bucketHash *cur;
	bucketHash *prev;
	
	while(signalTermThread[NumThreadProbe])
	{
		pthread_mutex_lock(&mutex_goCleaner);
		if(goCleaner==0)
		{
			//printf("\n\t# Thread Cleaner SOSPESO\n");
			pthread_cond_wait(&cond_goCleaner,&mutex_goCleaner);
			goCleaner=0;
		}
		pthread_mutex_unlock(&mutex_goCleaner);
		//printf("\n# Thread Cleaner IN ESECUZIONE\n");
		
		
		//ELIMINO GLI SCADUTI: SECOND CHANCE SCADUTA PER THREAD OPERATORE
		
		//printf("\n# Thread Cleaner: rimuovo scaduti\n");
		
		rimuoviScaduti();
		
		
		if(signalTermThread[NumThreadProbe]) //se non  mi sono risvegliato per ctrl+C
		{
			//CERCO NUOVI SCADUTI
		
			//printf("\n# Thread Cleaner: cerco scaduti\n");
			for(j=0;j<DimHash;j++)
			{
				cur=HashTable[j];
				prev=NULL;
				cont=0;
				while(cur!=NULL)
				{
					//(sono passati almeno globalTimeToExpire sec dall'ultimo aggiornamento del flusso) || (il flusso dura da localTimeToExpire sec) => flusso scaduto
					if((((cur->last_ts.sec)-(lastest.sec))>globalTimeToExpire) || (((cur->first_ts.sec)-(cur->last_ts.sec))>localTimeToExpire))
					{
						cont++;
						//printf("\n# Thread Cleaner: scaduto TABHASH[%d][%d]\n",j,cont);
						if(inserisciScaduto(cur)<1) //se non ho inserito il flusso scaduto nella coda fsc
						{
							printf("\n# Thread Cleaner: impossibile inserire flusso scaduto\n");
						}
						else
						{
							//aggiorno puntatori: non essendoci mutex, posso perdere dei pacchetti se il bucket successivo non esiste e un thread operatore lo crea nel frattempo
							/*
							printf("\n\tLASTEST: %ld",lastest.sec);
							printf("\n\tfirst_ts: %ld | last_ts: %ld",cur->first_ts.sec, cur->last_ts.sec);
							*/
							if(prev==NULL)
							{
								if((cur->next)!=NULL)
								{	
									HashTable[j]=cur->next;
								}
								else
								{
									HashTable[j]=NULL;
								}
							}
							else
							{
								if((cur->next)!=NULL)
								{	
									prev->next=cur->next;
								}
								else
								{
									prev->next=NULL;
								}							
							}
							cur=cur->next;						
						}
					}
					else
					{
						prev=cur;
						cur=cur->next;
					}
				}
			}
		}
	}
	
	//svuoto la tabella hash con i flussi pendenti
	
	liberaHash();
	
	pthread_exit(0);	
}


