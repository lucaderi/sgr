#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
void lettura(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p){
	unsigned char uno;
	int i=0;
	char* tempo;
	unsigned short int portas;
	unsigned short int portad;
	time_t secondi =h->ts.tv_sec;
	suseconds_t micro = h->ts.tv_usec;
	tempo= asctime(localtime(&secondi));
	memcpy(&portas,p+34,2);
	memcpy(&portad,p+36,2);
	portad= ntohs(portad);
	portas= ntohs(portas);
	char protocollo=*(p+23);
	printf("microsecondi %d    %s",micro,tempo);
	if(protocollo == 6){
	printf("protocollo = TCP\n");
	}
	else if(protocollo == 11){
	printf("protocollo = UDP\n");
	}
	else{printf("protocollo = TCP\n");
	}
	printf("sorgente ");
	for(i=26;i<30;i++){
	uno=*(p+i);
	printf("%d ",uno);
	}
	printf(":%d\n",portas);
	printf("destinazione ");
	for(i=30;i<34;i++){
	uno=*(p+i);
	printf("%d ",uno);
	}
	printf(":%d\n\n",portad);
}
int main(int argc, char *argv[]){
	bpf_u_int32 net,mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * nuovo;
	pcap_if_t * lista;
	int errore;
	/*errore = pcap_findalldevs(&lista,errbuf);
	printf("errore %d\n",errore);
	while(lista!= NULL){
		printf("interfaccia %s %s\n",lista->name, lista->description);
		lista=lista->next;
	}*/
	if(argc <3){
	printf("usage:\n reader -if [net interface] \n reader -file [pathname]\n");
	exit(1);
	}
	if(strcmp(argv[1],"-if")==0){
		nuovo=pcap_open_live(argv[2],65535,0,10000,errbuf);
	}
	else if(strcmp(argv[1],"-file")==0){
		nuovo=pcap_open_offline(argv[2],errbuf);
	}
	else exit(1);
	pcap_loop(nuovo,-1,lettura,NULL);


	return(0);
	}
