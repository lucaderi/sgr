
//struttura che definisce il messaggio scambiato tra client e server
typedef struct
{
	unsigned int length; 	//lunghezza in byte
	char* buffer;        	//buffer messaggio
}packet_t;



/** Scrive un messaggio sulla socket
 *   PARAM
 *   	fd  file descriptor della socket
 *   	pkt struttura che contiene il messaggio da scrivere
 *   RETURN
 *   	n   il numero di caratteri inviati (se scrittura OK)
 *   	-1  in caso di errore (imposta erno)
 */
int sendPacket(int fd,packet_t* pkt);




/** Legge un messaggio dalla socket
 *   PARAM
 *  	fd   file descriptor della socket
 *   	pkt  struttura che conterra' il messagio letto
 *		(deve essere allocata all'esterno della funzione,tranne il campo buffer)
 *
 *  RETURN
 *  	lung lunghezza del buffer letto, se OK
 *  	-1   in caso di errore (imposta errno)
 *
 */
int receivePacket(int fd,packet_t* pkt);


