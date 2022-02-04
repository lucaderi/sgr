
#include <pcap.h>
#include <stdio.h>
#include "rrd.h"
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <limits.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>

#define SNAP_LEN 84 //quantita del pacchetto da catturare
#define ET_HDR_LEN 14 //lunghezza pacchetto ehternet
#define NOW_PARAM "N" // indica il tempo attuale nei parametri del comando rrd_graph


static char *rrd_name="myrrd.rrd";
static char *iface="lo";
static char *gname="grafico.png";
static int threshold=40;//valore della soglia (40 pkt per secondo).
static int diff; //valore della differenza SYNACK - SYN



/*
 * Funzione del thread che si occupa di generare allarme e  grafico
 */
void *myfunc(void *id){


	int threshold_counter=0;
	int int_counter=0;
	int rate=0;
	int prev=0;
	while(1){


		rate=*((int *)id);
		int derive=(rate-prev);
		prev=rate;

		struct timeval tv = {1, 0};
		if (select(0, NULL, NULL, NULL, &tv) < 0) perror("select");


		//Messaggi di allerta
		if(derive>=threshold || derive <=-threshold){
			//se la soglia è stata superata più di 3 volte di seguito lancia un allarme più specifico
			if(threshold_counter>=4 ){
				fprintf(stdout,"WARNING:Possibile attacco SYNFLOOD o PORT SCANNING\n");
			}else{
				fprintf(stdout,"WARNING:Soglia superata\n");
				threshold_counter++;
			}
		}else{
			threshold_counter=0;
		}




		//genero l'update e lo inserisco nel RRA
		char *tbuf=malloc(sizeof(char)*10);
		sprintf(tbuf, "%s:%d", "N",rate);
		char *updateparams[] = {
				"rrdupdate",
				rrd_name,
				tbuf,
				NULL
		};
		if(rrd_update(3,updateparams)==-1){
			fprintf(stdout,"Aggiornamento database fallito\n");
		}

		free(tbuf);

		if((int_counter==5)){// ogni 5 intervalli di tempo disegna il grafico

			char **calcpr  = NULL;
			int  xsize, ysize;
			double ymin, ymax;

			char def[70];//parametro che indica il DS che devo prendere dal mio RRA.
			sprintf(def, "DEF:rate=%s:Rate:LAST", rrd_name);


			char baddef[70];
			sprintf(baddef, "CDEF:bad=rate,%d,GT,rate,rate,%d,LT,rate,0,IF,IF",threshold,-threshold);
			char warningdef[70];
			sprintf(warningdef, "CDEF:warning=rate,%d,GT,rate,rate,%d,LT,rate,0,IF,IF",threshold-10,-threshold-10);
			char gooddef[70];
			sprintf(gooddef, "CDEF:good=rate,%d,GT,0,rate,%d,GT,rate,0,IF,IF",threshold-10,-threshold-10);
			//insieme dei parametri per la generazione del grafico
			char *rrdgraphargs[] = {
					"rrdgraph",
					gname,//nome file
					def,//DS del RRA
					baddef, // x>40 e X<-40
					warningdef,// x>30 e x<-30
					gooddef,// 30-<x<30
					"AREA:good#00FF00:Good ",
					"AREA:warning#FFFF00:Warning",
					"AREA:bad#550000:Bad",
					"LINE2:rate#000000",//disegna linea del rate
					"LINE2:0#000000",//disegna una linea nera lungo l'asse X
					"--width",
					"800",
					"--start",// il grafo rappresenta sempre gli ultimi 60 secondi di tempo
					"end -60s",
					"--end",
					NOW_PARAM,//now
					"-v",
					"d(SynAck-Syn)/ds",
					"--x-grid",// visualizza lungo l'asse X il tempo ogni 5s
					"SECOND:1:SECOND:1:SECOND:5:0:%Ss",
					"-L",
					"5",
					"--alt-y-grid",
					NULL
			};

			rrd_graph(24, rrdgraphargs, &calcpr, &xsize, &ysize, NULL, &ymin, &ymax);

			int_counter=0;
		}

		int_counter++;



	}


}

/*
 * Funzione che gestisce i pacchetti catturati
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){





	struct ether_header *ethernet=(struct ether_header *) packet;
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){//se il BFP filter è attivo questo controllo  e quelli sucessivi sono inutili

		struct ip* iphdr;
		struct tcphdr* tcphdr;
		packet += ET_HDR_LEN;//imposto il puntatore del pacchetto su quello ip



		iphdr = (struct ip*)packet;


		if(iphdr->ip_p==IPPROTO_TCP){

			//imposto il puntatore del pacchetto sul header tcp
			packet+= 4*iphdr->ip_hl;

			tcphdr = (struct tcphdr*)packet;

			//aggiorno il contatore
			if(tcphdr->syn && !tcphdr->ack  ){//trovo un SYN
				diff--;
			}


			if(tcphdr->syn && tcphdr->ack){//trovo un ACK
				diff++;
			}

		}

	}else if(ntohs (ethernet->ether_type) == ETHERTYPE_IPV6){
		struct ip6_hdr* iphdr;

		packet += ET_HDR_LEN;
		iphdr = (struct ip6_hdr*)packet;

		if(iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt==IPPROTO_TCP){//se ci sono extension header nel pacchetto non li vedo

			//imposto il puntatore del pacchetto sul header tcp
			packet+= 40;//lunghezza header ipv6 senza extension header è di 40 bytes
			struct tcphdr* tcphdr;
			tcphdr = (struct tcphdr*)packet;

			//aggiorno il contatore
			if(tcphdr->syn && !tcphdr->ack  ){//trovo un SYN
				diff--;
			}


			if(tcphdr->syn && tcphdr->ack){//trovo un ACK
				diff++;
			}
		}
	}
}

//Converte la stringa in un intero.
int strtoint(char *in_str){

	int num;
	int lnum;

	lnum=strtol(in_str, (char **)NULL, 10);


	if ( (lnum > INT_MAX) || (lnum < INT_MIN) )
		fprintf(stderr, "ERROR: number out of range for INT\n");

	num=(int) lnum;

	return num;

}


int main(int argc, char *argv[]){


	int gflag=0,iflag=0,hflag=0,nflag=0,tflag=0;;
	opterr = 0;
	int c;

	while ((c = getopt (argc, argv, "i:n:g:t:h")) != -1)
		switch (c)
		{
		case 'i':
			if(iflag){
				fprintf (stderr,
						"Formato parametri errato, digita -h per una guida rapida\n");
				return 1;
			}
			gflag = 1;
			iface=optarg;
			break;
		case 'g':
			if(gflag){
				fprintf (stderr,
						"Formato parametri errato, digita -h per una guida rapida\n");
				return 1;
			}
			iflag = 1;
			gname=optarg;
			break;
		case 'n':
			if(nflag ){
				fprintf (stderr,
						"Formato parametri errato, digita -h per una guida rapida\n");
				return 1;
			}
			nflag = 1;
			rrd_name=optarg;
			break;
		case 't':
			if(tflag){
				fprintf (stderr,
						"Formato parametri errato, digita -h per una guida rapida\n");
				return 1;
			}
			tflag = 1;

			threshold=strtoint(optarg);
			if(threshold<=0){
				fprintf (stderr,
						"Inserito un valore per la soglia non valido\n");
				return 1;
			}
			break;
		case 'h':
			hflag=1;
			break;
		case '?':
			fprintf (stderr,
					"Formato parametri errato, digita -h per una guida rapida\n");
			return 1;
		default:
			break;
		}

	if(hflag){
		fprintf(stdout,"Digitare  sfd [options]\n\t -i [interface]: per specificare l'interfaccia di cattura, il valore di default è lo.");
		fprintf(stdout,"\n\t -n [value]: per specificare il nome del RRA.Il nome di default è myrrd.rrd");
		fprintf(stdout,"\n\t -t [value]: per cambiare il valore della soglia. Il valore di default è 40");
		fprintf(stdout,"\n\t -g [value]: per cambiare il nome del grafico. Il nome di default è grafico.png");
		fprintf(stdout,"\n\t -h [value]: per stampare questo messaggio.\n");
		return(1);
	}


	diff=0;//inizializzo a zero il valore della differenza

	//parametri per la crazione del RRA
	//Il valore che si è scelto di memorizzare è la derivata rispetto al tempo della differenza tra syn-synack
	//La derivata indica quanto cresce questa differenza. Quando questa differenza supera la soglia allora c'e' una anomalia.
	char *createparams[] = {
			"rrdcreate",
			rrd_name,
			"--start=now",
			"--step=1",//il mio rra si aspetta dati ad ogni secondo
			"DS:Rate:DERIVE:10:U:U",
			"RRA:LAST:0.999:1:60",//mantieni un rra per 60 record(ovvero in questo caso 60 secondi)
			NULL
	};
	if (rrd_create(6, createparams)==-1){
		fprintf(stderr, "Impossibile creare il database.\n");
		exit(EXIT_FAILURE);
	}

	pcap_t *handle;

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		// Struct per il filter
	char filter_exp[] = "(tcp-syn) != 0";


	if (iface == NULL) {
		fprintf(stderr, "Impossibile trovare la device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	handle = pcap_open_live(iface, SNAP_LEN, 1,0, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Impossibile aprire la device%s: %s\n", iface, errbuf);
		exit(EXIT_FAILURE);
	}

	//controllo che sia una device ethernet
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s non è un device ethernet\n", iface);
		exit(EXIT_FAILURE);
	}

	if(pcap_set_datalink(handle,DLT_EN10MB)<0){
		fprintf(stderr, "impossibile settare il datalink%s\n", iface);
		exit(EXIT_FAILURE);
	}


	//Compilo  e setto il filtro
	int bool_filter=1;
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Errore nell'espressione del filtro %s: %s\n", filter_exp, pcap_geterr(handle));
		bool_filter=0;
	}

	if (bool_filter && pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Impossibile installare il filtro %s: %s\n", filter_exp, pcap_geterr(handle));
	}


	//creo il thread per la generazione degli allarmi  e del grafico,
	pthread_t rrd_thread;
	pthread_create(&rrd_thread,NULL,myfunc,&diff);

	fprintf(stdout, "Inizio cattura dei pacchetti sull 'interfaccia %s, il valore della soglia è %d.\n",iface,threshold);
	fprintf(stdout,"Per visualizzare il grafico aprire il file %s\n",gname);
	if(pcap_loop(handle,0, got_packet, NULL)==-1)
		fprintf(stderr, "Impossibile eseguire la cattura dei pacchetti: %s\n", pcap_geterr(handle));

	pcap_close(handle);

	return(0);
}
