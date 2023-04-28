#include "dependencies.h"

/*
	Generica funzione di calcolo del checksum
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*) ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void psender_udp(int s, char* ipsrc, char *address)
{
	char datagram[4096], source_ip[32], *data , *pseudogram;
	
	//datagram impostato totalmente a 0
	memset (datagram, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	
	/*
		Socket Address
        Describes  an IPv4 Internet domain socket address.  The sin_port and sin_addr
        members are stored in network byte order.

		struct sockaddr_in {
           sa_family_t     sin_family;     AF_INET 
           in_port_t       sin_port;       Port number
           struct in_addr  sin_addr;       IPv4 address
       };
	*/
	struct sockaddr_in sin;	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data , "THAMMER");
	
	//some address resolution
	strcpy(source_ip , ipsrc);
	
	/*
		AF_INET is an address family that is used to designate the type of addresses 
		that your socket can communicate with (in this case, Internet Protocol v4 addresses).
		When you create a socket, you have to specify its address family, and then you can 
		only use addresses of that type with the socket.
	*/
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr (address);
	
	//Procediamo alla creazione del header IP
	//Internet Header Length is the length of the internet header in 32 bit words
	iph->ihl = 5;
	iph->version = 4;
	//Type Of Service
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	iph->id = htonl (54321);	//Id of this packet
	//Fragment Offset
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	//checksum da calcolare
	iph->check = 0;
	//IP sorgente e destinazione
	iph->saddr = inet_addr ( source_ip );
	iph->daddr = sin.sin_addr.s_addr;
	
	//IP checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//Procediamo con la creazione del header UDP
	//Porta di ingresso
	udph->source = htons (6666);
	//Porta destinazione
	udph->dest = htons (9090);
	//Lunghezza
	udph->len = htons(8 + strlen(data));
	//Checksum facoltativo in UDP
	udph->check = 0;
	
	//for(int i = 0; i<20;i++)
	{
		//Inviare il pacchetto
		if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
			perror("sendto failed");
		}
		//Inviato con successo
		//printf ("Packet Send. Length : %d, ip: %s\n" , iph->tot_len, ipsrc);
	}
}