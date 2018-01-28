
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "utility.h"

int sendPacket(int fd,packet_t* pkt)
{
	//temporanei
	int byte_written;
	int tmp;

	//controllo validità parametro d'ingresso
	if ( (pkt == NULL)||(pkt->length == 0 && pkt->buffer != NULL) )
	{
		errno = EINVAL;
		return -1;
	}

	//invio sul socket lunghezza del messaggio
	//(in realtà invio anche il puntatore al buffer ma questo valore non è chiaramente significativo)
	byte_written = 0;
	while (byte_written != sizeof(*pkt))
	{
		tmp = write(fd,pkt+byte_written,sizeof(*pkt)-byte_written);
		if (tmp == -1)
		{
			return -1;
		}
		else
		{
			byte_written += tmp;
		}
	}

	//...se sono arrivato fino a qui vuol dire che la struttura(lunghezza)è stata scritta correttamente su
	//socket...passo ad inviare il messaggio vero e proprio
	byte_written = 0;
	while(byte_written != pkt->length)
	{
		tmp = write(fd,pkt->buffer+byte_written,pkt->length-byte_written);
		if (tmp == -1)
		{
			return -1;
		}
		else
		{
			byte_written += tmp;
		}
	}

	// se sono arrivato fin qui vuol dire che ho scritto esattamente pkt->length sul socket
	return pkt->length;
}



int receivePacket(int fd,packet_t* pkt)
{
	//temporanei
	int byte_read;
	int tmp;

	//leggo dal socket lunghezza del messaggio, il campo puntatore non e' significativo
	byte_read = 0;
	while(byte_read != sizeof(packet_t))
	{
		tmp = read(fd,pkt+byte_read,sizeof(packet_t)-byte_read);
		if ( (tmp == -1)||(tmp == 0) )
		{
			return -1;
		}
		else
		{
			byte_read += tmp;
		}
	}


	//alloco buffer per il messaggio, se necessario,
	//e mi metto in attesa di ricevere il messaggio vero e proprio
	if (pkt->length != 0)
	{
		pkt->buffer = (char*)malloc(pkt->length);
		if (pkt->buffer == NULL)
		{
			return -1;
		}

		byte_read = 0;
		while(byte_read != pkt->length)
		{
			tmp = read(fd,pkt->buffer+byte_read,pkt->length-byte_read);
			if (tmp == -1)
			{
				return -1;
			}
			else
			{
				byte_read += tmp;
			}
		}

	}

	//se sono arrivato fino a qui vuol dire che il messaggio e' stato ricevuto correttamente
	return pkt->length;

}


/*
int sendPacket(int fd,packet_t* pkt)
{
	//controllo validità parametro d'ingresso
	if ( (pkt == NULL)||(pkt->length == 0 && pkt->buffer != NULL) )
	{
		errno = EINVAL;
		return -1;
	}

	//invio sul socket lunghezza del messaggio
	//(in realtà invio anche il puntatore al buffer ma questo valore non è chiaramente significativo)
	int byte_written = write(fd,(packet_t*)pkt,sizeof(*pkt));

	//se non sono riuscito a scrivere la struttura sul socket
	if (byte_written != sizeof(*pkt))
	{
		if (byte_written != -1)
		{
			errno = EIO;
		}
		return -1;
	}

	//...se sono arrivato fino a qui vuol dire che la struttura(lunghezza)è stata scritta correttamente su
	//socket...passo ad inviare il messaggio vero e proprio

	byte_written = write(fd,pkt->buffer,pkt->length);

	//se non sono riuscito a scrivere il messaggio sul socket
	if (byte_written != pkt->length)
	{
		if (byte_written != -1)
		{
			errno = EIO;
		}
		return -1;
	}

	// se sono arrivato fin qui vuol dire che ho scritto esattamente pkt->length sul socket
	return pkt->length;
}



int receivePacket(int fd,packet_t* pkt)
{
	//leggo dal socket lunghezza del messaggio, il campo puntatore non e' significativo
	int byte_read = read(fd,(packet_t*)pkt,sizeof(packet_t));

	//controllo di aver letto esattamente sizeof(packet_t) byte
	if (byte_read != sizeof(packet_t))
	{
		return -1;
	}

	//alloco buffer per il messaggio, se necessario,
	//e mi metto in attesa di ricevere il messaggio vero e proprio
	if (pkt->length != 0)
	{
		pkt->buffer = (char*)malloc(pkt->length);
		if (pkt->buffer == NULL)
		{
			return -1;
		}

		byte_read = read(fd,pkt->buffer,pkt->length);

		//controllo di aver letto esattamente pkt->length byte
		if (byte_read != pkt->length)
		{
			return -1;
		}
	}

	//se sono arrivato fino a qui vuol dire che il messaggio e' stato ricevuto correttamente
	return pkt->length;

}
*/
