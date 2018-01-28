
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include<linux/if_packet.h>
#include "utility.h"

#define DIM 2048							//dimensione buffer per contenere pacchetto dal socket raw
#define STRERR "Impossibile proseguire"		//messaggio di errore

#define CHECK_ERROR()\
({\
	if (result != 0)\
	{\
		perror("Impossibile gestire segnali");\
		printf("server terminato\n");\
		return -1;\
	}\
})


//variabili globali
static int active_socket;               //socket utilizzato per comunicare con il client
static int passive_socket;              //socket dal quale il server riceve la richiesta di connessione
static int sniffing_socket;				//socket dal quale il server cattura i pacchetti
static packet_t packet;					//messaggio da spedire al client
static unsigned int pkt_counter;		//contatore pacchetti catturati
FILE* log_file;							//puntatore al file di log

//====================================================================================================================================


/**
 * gestore segnale SIGINT\SIGTERM
 */
void sig_handler()
{
	//chiudo socket aperti e file di log

	fflush(log_file);
	fclose(log_file);
	close(passive_socket);
	close(sniffing_socket);
	close(active_socket);
	free(packet.buffer);

	printf("pacchetti catturati e spediti: %u\nserver terminato\n",pkt_counter);

	exit(EXIT_SUCCESS);
}


/** aggancia un socket ad un' interfaccia
     PARAM
     	device   nome dell'interfaccia
     	rawsock  socket raw
     	protocol tipo di protocollo

     RETURN
     	-1 in caso di errore(imposta errno)
     	 0 altrimenti
 */
int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(ifr));

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		return -1;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);

	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		return -1;
	}

	return 0;
}



int main(int argc,char* argv[])
{
	//inizializzazione

    unsigned short int port;		        //porta sullla quale il server e' in ascolto
    struct ifreq interface;					//struttura che descrive l'interfaccia con cui comunicare con il client
    struct sockaddr_in address;             //struttura che contiene l'indirizzo del server
    struct sigaction sig_int;				//struttura che definisce il trattamento del segnale SIGINT
    struct sigaction sig_term;				//struttura che definisce il trattamento del segnale SIGTERM
    struct sigaction sig_pipe;				//struttura che definisce il trattamento del segnale SIGPIPE
    int result;                             //esito generica operazione

    //gestione dei segnali

    sig_pipe.sa_handler = SIG_IGN;						//ignoro SIGPIPE

    result = sigaction(SIGPIPE,&sig_pipe,NULL);			//installo gestore SIG_PIPE
    CHECK_ERROR();

    memset(&sig_int,0,sizeof(sig_int));
    memset(&sig_term,0,sizeof(sig_term));

    sig_int.sa_handler = sig_handler;					//imposto lo stesso gestore per i segnali
    sig_term.sa_handler = sig_handler;					//

    result = sigaddset(&(sig_int.sa_mask),SIGTERM); 	//durante la gestione di SIGINT maschero SIGTERM...
    CHECK_ERROR();

    result = sigaddset(&(sig_term.sa_mask),SIGINT);		//...e durante la gestione di SIGTERM maschero SIGINT
    CHECK_ERROR();

    result = sigaction(SIGTERM,&sig_term,NULL);			//installo gestore SIG_TERM
    CHECK_ERROR();										//

    result = sigaction(SIGINT,&sig_int,NULL);			//installo gestore SIG_INT
    CHECK_ERROR();										//


    //controllo numero parametri d'ingresso
    if (argc != 5)
    {
    	fprintf(stderr,"Numero parametri non valido\n");
    	printf("server terminato\n");
    	return -1;
    }

    //controllo corretta apertura file di log
    log_file = fopen(argv[4],"w+");
    if (log_file == NULL)
    {
    	perror("Impossibile accedere al file di log");
    	printf("server terminato\n");
    	return -1;
    }

    //controllo valore porta
    port = atoi(argv[3]);
    if ( (atoi(argv[3]) < 1024)||(atoi(argv[3]) > 65535) )
    {
    	fclose(log_file);
    	fprintf(stderr,"Porta non valida\n");
    	printf("server terminato\n");
    	return -1;
    }
    port = atoi(argv[3]);


    //creo socket per ricevere richiesta di connessione del client
    passive_socket = socket(AF_INET,SOCK_STREAM,0);
    if (passive_socket == -1)
    {
    	perror("Impossibile proseguire");
    	fclose(log_file);
    	printf("server terminato\n");
    	return -1;
    }

    //dato il nome dell'interfaccia con cui comunicare con il client estraggo indirizzo IP
    strncpy((char *)interface.ifr_name, argv[2], IFNAMSIZ);
    result = ioctl(passive_socket,SIOCGIFADDR,&interface);
    if (result == -1)
    {
      	perror(STRERR);
      	fclose(log_file);
      	close(passive_socket);
      	printf("server terminato\n");
        return -1;
    }

    //cerco di eseguire la bind
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = (((struct sockaddr_in*)&(interface.ifr_addr))->sin_addr).s_addr;

    result = bind(passive_socket,(struct sockaddr*)&address,sizeof(address));
    if (result == -1)
    {
      	perror(STRERR);
      	fclose(log_file);
        close(passive_socket);
        printf("server terminato\n");
        return -1;
    }

    //cerco di eseguire la listen
    result = listen(passive_socket,1);
    if (result == -1)
    {
     	perror(STRERR);
     	fclose(log_file);
        close(passive_socket);
        printf("server terminato\n");
        return -1;
    }

    //creo socket da cui catturare pacchetti
    sniffing_socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (sniffing_socket == -1)
    {
       	perror(STRERR);
       	fclose(log_file);
       	close(passive_socket);
       	printf("server terminato\n");
      	return -1;
    }

    //collego il socket appena creato all'interfaccia specificata come parametro d'ingresso
    //in modo da catturare pacchetti esclusivamente da questa interfaccia
    result = BindRawSocketToInterface(argv[1],sniffing_socket,ETH_P_ALL);
    if (result == -1)
    {
       	perror(STRERR);
       	fclose(log_file);
        close(passive_socket);
        close(sniffing_socket);
        printf("server terminato\n");
        return -1;
    }

    //alloco memoria per catturare pacchetto
    packet.buffer = (char*)malloc(DIM);
    if (packet.buffer == NULL)
    {
      	perror(STRERR);
      	fclose(log_file);
       	close(passive_socket);
       	close(sniffing_socket);
       	printf("server terminato\n");
       	return -1;
    }

    printf("In attesa del client...\n");

    //attendo connessione da parte del client
    result = accept(passive_socket,NULL,0);
    if (result == -1)
    {
    	perror(STRERR);
    	fclose(log_file);
    	close(passive_socket);
    	close(sniffing_socket);
    	free(packet.buffer);
    	printf("server terminato\n");
        return -1;
    }

    active_socket = result;

    printf("Client connesso.\nCattura pacchetti in corso...\n");

    //inizio ciclo infinito di cattura
    while(1)
    {
    	//catturo pacchetto dal socket
    	int byte_read = read(sniffing_socket,packet.buffer,DIM);
    	if (byte_read == -1)
    	{
    		perror("Errore durante la cattura dei pacchetti");
    		fflush(log_file);
    		fclose(log_file);
    		close(passive_socket);
    		close(sniffing_socket);
    		close(active_socket);
    		free(packet.buffer);
    		printf("pacchetti catturati e spediti: %u\nserver terminato\n",pkt_counter);
    		return -1;
    	}

    	//aggiorna lunghezza messaggio da spedire
    	packet.length = byte_read;

    	//invio pacchetto appena catturato al client
    	result = sendPacket(active_socket,&packet);

    	if (result == -1)
    	{
    		//se il client ha chiuso la connessione non stampo l'errore in quanto la considero una terminazione "normale"
    		if (errno != EPIPE)
    		{
    			perror(STRERR);
    		}
    		fflush(log_file);
    		fclose(log_file);
    		close(passive_socket);
    		close(sniffing_socket);
    		close(active_socket);
    		free(packet.buffer);
    		printf("pacchetti catturati e spediti: %u\nserver terminato\n",pkt_counter);
    		return -1;
    	}

    	//memorizzo nel file di log
    	fprintf(log_file,"%10u %4d %4d\n",pkt_counter,byte_read,result);
    	//printf("%u - letti:%d spediti: %d\n",pkt_counter,byte_read,result);

    	//incremento contatore pacchetti catturati
    	pkt_counter++;
    }
}

