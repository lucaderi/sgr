//#include "sniffingDNS.h"

#include <pcap/pcap.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "creazioneBigrammi.h"
#include "grafoBigrammi.h"
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#define SIZE_UDP 8
#define SIZE_DNS_HEADER 12 
#define LENGHT_DNS_NAME 64

void help(){
	printf("cattura pacchetti online: \n"); 
	printf("	sudo ./dga -d <file> -b <file> [-p <val>] [-n <val>] [-i <interface>] [-m] [-h] \n");
	printf("cattura pacchetti offline: \n");
	printf("	sudo ./dga -d <file> -b <file> [-p <val>] [-f <file>] [-h] \n");
	printf("\n");
	printf("	-p 		limite probalilita \n");
 	printf("	-d 		nome del file contenente i nomi di domini per la creazione iniziale del grafo\n");
 	printf("	-f 		nome del file pcap per l'analisi offline\n");
 	printf("	-n 		numero pacchetti da sniffare\n");
 	printf("	-i 		nome interfaccia\n");
 	printf("	-m 		modalita promiscua \n");
 	printf("	-b 		nome file black list\n");
 	printf("	-h 		help\n");
 }

struct dns_header{
	int16_t id;
    unsigned short int rd : 1;
    unsigned short int tc : 1;
    unsigned short int aa : 1;
    unsigned short int opcode : 4;
    unsigned short int qr : 1;
    unsigned short int rcode : 4;
    unsigned short int z : 3;
    unsigned short int ra : 1;
    uint16_t  qcount;
    uint16_t  ancount;
    uint16_t  nscount; 
    uint16_t  adcount; 
};

struct dns{
	u_char* name;
};

int probabilitaSoglia = 50;
int num_packets = -1;
int modPromiscua = 0;
char* fileDominio = NULL;
char* fileBlackList = NULL;
char* nomeInterfaccia = NULL;
pcap_t * handle;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	struct ether_header* frameEth = (struct ether_header*)(packet);
    struct ip* ip = (struct ip*)(packet + ETH_HLEN);
    int size_ip = ip->ip_hl*4;
    struct udphdr* udp = (struct udphdr*)(packet+ETH_HLEN+size_ip);

    if(ntohs(udp->uh_dport)==53){
	    struct dns_header* dns_header = (struct dns_header*)(packet+ETH_HLEN+size_ip+ SIZE_UDP);
		if(dns_header->qr == 0){
			//stampa nome dominio
			u_char* dns = (u_char*)(packet+ETH_HLEN+size_ip+ SIZE_UDP + SIZE_DNS_HEADER);
		    char nameQuery[LENGHT_DNS_NAME];

			int fine=0;
			int i=1;
			while(!fine){
				char c = (char) dns[i];
				if (isprint(c)){
					nameQuery[i-1] = c;
					i++;
				}
				else{
					if(c=='\0'){
						nameQuery[i-1] = '\0';
						fine = 1;
					}
					else{
						nameQuery[i-1] = '.';
						i++;
					}
				}		
		    }

			int numeroBigrammi;
			char** bigrammiParola = bigrammiArray(nameQuery, &numeroBigrammi);
			int numeroSequenza = cercaSequenza(bigrammiParola, numeroBigrammi);
			double probabilita = (double) numeroSequenza / (double) numeroBigrammi*100;
			printf("%f%%	%s	%s\n",probabilita, inet_ntoa(ip->ip_src), nameQuery);
			if(probabilita<probabilitaSoglia){
				//ricerca blacklist
				FILE *fd;
				char* buf;
				size_t len =0;
				size_t read =0;
				int blacklist=0;
				fd=fopen(fileBlackList, "r");
				if(fd ==NULL)
					return;

				while ( (read = getline(&buf, &len, fd)) != -1)
					if(strcmp(nameQuery, buf)==0)
						blacklist=1;
				fclose(fd);

				if(!blacklist){
					int esito;
					printf("parola %s non è stata trovata. Aggiungere la nuova parola? [1=si, 0=no]\n", nameQuery);
					scanf("%d", &esito);
					if(esito)
						inserisciSequenza(bigrammiParola, numeroBigrammi);
				}
				else{
					printf("ERRORE: dominio in blacklist\n");
				}
				freeBiagrammaArray(bigrammiParola, numeroBigrammi);
			}
		}
	}
}

void snifferOffline(char* filepcap){
	char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_offline (filepcap, error_buffer);
    if(handle == NULL){
    	printf("Errore: %s\n", error_buffer );
    	return;
    }
	//utilizzo di pcap_loop
	printf("%s	%s		%s\n","probabilita", "ip", "nomeDns");
	pcap_loop(handle, num_packets, got_packet, NULL);
	//chiusura sessione
	pcap_close (handle);
}

void sniffingOnline(){
	//tovare le interfaccie
	char error_buffer[PCAP_ERRBUF_SIZE];

	//aggiungere lista di scelta per l'interfaccia
	if(nomeInterfaccia == NULL){
		pcap_if_t *interfaces;
   		if(pcap_findalldevs(&interfaces,error_buffer)==-1) {
        	return;   
    	}
    	int i=0;
    	printf("le interfaccie presenti nel sistema sono:\n");
    	for(pcap_if_t* temp=interfaces; temp; temp=temp->next){
        	printf("%d  :  %s\n",i++,temp->name);
    	}
    	printf("inserire il numero della interfaccia:  ");
		scanf("%d", &i);
		int j=0;
		for(pcap_if_t* temp=interfaces; temp; temp=temp->next){
        	if(j==i)
        		nomeInterfaccia = temp->name;
        	j++;
    	}
   	}

    //Apertura del dispositivo per lo sniffing
    handle = pcap_open_live(nomeInterfaccia, BUFSIZ, modPromiscua, num_packets*2, error_buffer);
    if(handle == NULL){
    	printf("Errore: %s\n", error_buffer );
    	return;
    }

    //creazione di un filtro
    struct bpf_program fp;
    char* string_filter= "port 53";

   	bpf_u_int32 net;
	bpf_u_int32 mask;
	if (pcap_lookupnet (nomeInterfaccia, &net, &mask, error_buffer) == -1) {
		printf("ERRORE\n");
		return;
	}
	if (pcap_compile (handle, &fp, string_filter, 0, net) == -1) {
		printf("ERRORE\n");
		return;
	}
	if (pcap_setfilter (handle, &fp) == -1) {
		printf("ERRORE\n");
		return;
	}

	printf("%s	%s		%s\n","probabilita", "ip", "nomeDns");
	pcap_loop(handle, num_packets, got_packet, NULL);
	//chiusura sessione
	pcap_close (handle);
}

void terminazione(){
	grafoFree();
	pcap_close (handle);
	exit(0);
}

int main(int argc, char* argv[]){
	//file di configurazione -f
	int arg;
	char* filepcap = NULL;
	signal(SIGINT, terminazione);
	while((arg = getopt(argc, argv, "p:d:f:n:i:mb:h")) != -1) {
 		switch (arg) {
 			case 'p':{
 				//limite probabilita 
 				int p = atoi(optarg);
 				if(p<=100)
 					probabilitaSoglia = p;
 				else{
 					printf("Errore: valore <= 100\n");
 					return 1;
 				}
 				break;
 			}
 			case 'd':{
 				fileDominio = optarg;
 				break;
 			}
 			case 'f':{
 				filepcap = optarg;
 				break;
 			}
 			 case 'n':{
 				num_packets = atoi(optarg);
 				break;
 			}
 			case 'i':{
 				nomeInterfaccia = optarg;
 				break;
 			}
 			case 'm':{
 				modPromiscua = 1;
 				break;
 			}
 			case 'b':{
				fileBlackList = optarg;
 				break;
 			}
 			case 'h':{
 				help();
 				return 0;
 			}
 		}
	}

	//creazione iniziale del grafo 
	if(fileDominio != NULL && fileBlackList != NULL){
		FILE *fd;
		char* buf;
		size_t len =0;
		size_t read =0;
		char* res;
		fd=fopen(fileDominio, "r");
		if(fd ==NULL)
			return 1;
		while ( (read = getline(&buf, &len, fd)) != -1){
			int numeroBigrammi;
			char** bigrammi = bigrammiArray(buf, &numeroBigrammi);
			inserisciSequenza(bigrammi, numeroBigrammi);
			freeBiagrammaArray(bigrammi, numeroBigrammi);
		}
		fclose(fd);

		if(filepcap==NULL){
			sniffingOnline();
		}
		else{
			snifferOffline(filepcap);
		}
	}
	else{
		if(fileDominio == NULL)
			printf("ERRORE: inserire nome file con la lista dei file di dominio: -d <file>\n");
		if(fileBlackList==NULL)
			printf("ERRORE: inserire nome file con la blacklist: -b <file>\n");
	}

    return 0;
}
