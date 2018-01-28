
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "utility.h"

#define VIRTUAL_IF_NAME "remote_interface"		//nome interfaccia remota
#define DIM 2048								//dimensione buffer per contenere pacchetto in arrivo dal server
#define STRERR "Impossibile proseguire"			//messaggio di errore

#define CHECK_ERROR()\
({\
	if (result != 0)\
	{\
		perror("Impossibile gestire segnali");\
		printf("client terminato\n");\
		return -1;\
	}\
})


//variabili globali
static int sock;					//socket utilizzata per comunicare con il server
static int tapfd;					//file descriptor utilizzato per comunicare con l'interfaccia virtuale
static unsigned int count;			//contatore pacchetti ricevuti


//====================================================================================================================================


/**
 * gestore segnale SIGINT\SIGTERM
 */
void sig_handler()
{
	//chiudo socket

	close(sock);
	close(tapfd);

	printf("pacchetti catturati: %u\nclient terminato\n",count);

	exit(EXIT_SUCCESS);
}



/* Crea un'interfaccia virtuale
 *  PARAM
 *  	dev   nome interfaccia virtuale da creare
 *  	flags flag da impostare
 *  RETURN
 *  	fd file descriptor interfaccia creata
 *  	-1 in caso di errore(imposta errno)
 *
 */
int tun_alloc(char *dev, int flags)
{

	struct ifreq ifr;
	int fd = -1, err;
	char *clonedev = "/dev/net/tun";

	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	  * int flags: interface flags (eg, IFF_TUN etc.)
	 */

	 /* open the clone device */
	if( (fd = open(clonedev, O_RDWR)) < 0 )
	{
		return fd;
	}

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

	((struct sockaddr_in*)&ifr)->sin_addr.s_addr = inet_addr("0.0.0.0");

	if (*dev)
	{
		 /* if a device name was specified, put it in the structure; otherwise,
		  * the kernel will try to allocate the "next" device of the
		  * specified type */
		 strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
	{
		close(fd);
		return err;
	}

	/* if the operation was successful, write back the name of the
	 * interface to the variable "dev", so the caller can know
	 * it. Note that the caller MUST reserve space in *dev (see calling
	 * code below) */
	strcpy(dev, ifr.ifr_name);

	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}


/* Attiva un'interfaccia virtuale
 *  RETURN
 *  	-1 in caso di errore(imposta errno)
 *  	 0 altrimenti
 *
 */
int set_interface_up()
{
	//inizializzazione
	char* command;			//stringa comando
	int result;				//esito generica operazione

	command = (char*)malloc(18+strlen(VIRTUAL_IF_NAME));
	if (command == NULL)
	{
		return -1;
	}

	sprintf(command,"sudo ifconfig %s up",VIRTUAL_IF_NAME);
	result = system(command);
	free(command);

	return result;
}

int main(int argc,char* argv[])
{
	//inizializzazione

	struct sockaddr_in address;     	//struttura che contiene l'indirizzo del server
	int port;							//porta sulla quale il server è in ascolto
	packet_t packet;					//messaggio in arrivo dal server
	char tap_name[IFNAMSIZ];			//nome interfaccia virtuale
	struct sigaction sig_term;			//struttura che definisce il trattamento del segnale SIGTERM
	struct sigaction sig_int;			//struttura che definisce il trattamento del segnale SIGINT
	int result;                         //esito generica operazione

	//gestione dei segnali

	memset(&sig_int,0,sizeof(sig_int));
	memset(&sig_term,0,sizeof(sig_term));

	sig_int.sa_handler = sig_handler;					//imposto lo stesso gestore per entrambi i segnali
	sig_term.sa_handler = sig_handler;					//

	result = sigaddset(&(sig_int.sa_mask),SIGTERM); 	//durante la gestione di SIGINT maschero SIGTERM...
	CHECK_ERROR();

	result = sigaddset(&(sig_term.sa_mask),SIGINT);		//...e durante la gestione di SIGTERM maschero SIGINT
	CHECK_ERROR();

	result = sigaction(SIGTERM,&sig_term,NULL);			//installo gestore SIG_TERM
	CHECK_ERROR();										//

	result = sigaction(SIGINT,&sig_int,NULL);			//installo gestore SIG_IN
	CHECK_ERROR();										//


	//controllo numero parametri d'ingresso
	if (argc != 3)
	{
	  	fprintf(stderr,"Numero parametri non valido\n");
	  	printf("client terminato\n");
	  	return -1;
	}

	//controllo valore porta
	port = atoi(argv[2]);
	if ( (atoi(argv[2]) < 1024)||(atoi(argv[2]) > 65535) )
	{
	  	fprintf(stderr,"Porta non valida\n");
	  	printf("client terminato\n");
	  	return -1;
	}
	port = atoi(argv[2]);

	//creo interfaccia virtuale
	strcpy(tap_name,VIRTUAL_IF_NAME);
	tapfd = tun_alloc(tap_name, IFF_TAP|IFF_NO_PI);
	if (tapfd == -1)
	{
		perror("Impossibile creare interfaccia virtuale");
		printf("client terminato\n");
		return -1;
	}

	//imposto l'interfaccia virtuale appena creata a UP
	result = set_interface_up(tapfd);
	if (result == -1)
	{
		fprintf(stderr,"Impossibile attivare interfaccia virtuale\n");
		close(tapfd);
		printf("client terminato\n");
		return -1;
	}

	//creo socket per comunicare con il server
	sock = socket(AF_INET,SOCK_STREAM,0);
	if (sock == -1)
	{
	  	perror(STRERR);
	  	close(tapfd);
	  	printf("client terminato\n");
	   	return -1;
	}

	//cerco di eseguire la connect
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = inet_addr(argv[1]);

	result = connect(sock,(struct sockaddr*)&address,sizeof(address));
	if (result == -1)
	{
		perror(STRERR);
		close(sock);
		close(tapfd);
		printf("client terminato\n");
		return -1;
	}

	printf("Connessione al server stabilita.\nElaborazione in corso...\n");

	//inizio ciclo infinito di "cattura remota"
	while(1)
	{
		//ricevo pacchetto dal server
		int byte_read = receivePacket(sock,&packet);
		if (byte_read == -1)
		{
			//se il server ha chiuso la connessione non stampo l'errore in quanto la considero una terminazione "normale"
			if (errno != 0)
			{
				perror(STRERR);
			}
			close(sock);
			close(tapfd);
			printf("pacchetti catturati: %u\nclient terminato\n",count);
			return -1;
		}

		//scrivo su interfaccia virtuale
		result = write(tapfd,packet.buffer,packet.length);
		if (result != packet.length)
		{
			close(sock);
			close(tapfd);
			printf("pacchetti catturati: %u\nclient terminato\n",count);
			return -1;
		}

		//incremento contatore pacchetti ricevuti
		count++;
		//printf("%u - %u byte\n",count,packet.length);

		free(packet.buffer);
		packet.length = 0;
	}
}
