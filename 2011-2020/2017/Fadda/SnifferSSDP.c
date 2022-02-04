/*
    Gestione di rete:
    Sniffer SSDP
    Author: Claudio Fadda (mat.430988)
 	To compile: gcc GestioneDiRete.c  -lpcap -o SnifferSSDP

 */
#include<pcap.h>
#include<stdio.h>
#include<signal.h>
#include<stdlib.h>
#include<string.h>

#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/ip.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_udp_packet(const u_char * , int);
void PrintData (const u_char * , int);
void INThandler(int);



FILE *logfile;
struct sockaddr_in source,dest;
int header_size;
int udp=0;
char locations[400][400];
int indloc=0;

int main()
{
	pcap_t *handle; //Handle of the device that shall be sniffed
	char inst[50];
	signal(SIGINT, INThandler);

	pcap_if_t *alldevsp , *device;
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	logfile=fopen("log.txt","w+");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}
	strncpy(inst, "gssdp-discover --timeout=7 -i ", 40);
	strcat(inst, devname);
	strcat(inst," >/dev/null &");
	system(inst);

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	if(iph->protocol == 17){
		print_udp_packet(buffer , size);
		udp++;
	}
	printf("UDP packets : %d   \r",udp);
}


void print_ip_header(const u_char * Buffer, int Size)
{
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	fprintf(logfile , "\n\n				-----| Source device: %s |-----\n\n" , inet_ntoa(source.sin_addr) );
}


void print_udp_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	if(ntohs(udph->source) == 1900){
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
		//Move the pointer ahead and reduce the size of string
		if((Buffer + header_size)[0] != 'M'){


			PrintData(Buffer + header_size , Size - header_size);

		}
	}
}



int findSubstr(char *inpText, char *pattern) {
	int inplen = strlen(inpText);
	while(inpText != NULL) {

		char *remTxt = inpText;
		char *remPat = pattern;


		if(strlen(remTxt) < strlen(remPat)) {
			return -1;
		}

		while (*remTxt++ == *remPat++) {
			if(*remPat == '\0' ) {
				return inplen - strlen(inpText+1) ;
			}
			if(remTxt == NULL) {
				return -1;
			}

		}
		remPat = pattern;

		inpText ++;
	}
	return -1;
}








void PrintData (const u_char * data , int Size)
{
	int i , j, k =0, temp, first, second, flag =0, pos_location=2;
	char first_str[300]={0x0},second_str[300]={0x0};
	first =  findSubstr((char *)data, "Server");
	if(first ==-1)first =  findSubstr((char *)data, "SERVER");

	second = findSubstr((char *)data,"Location");
	if(second == -1) second = findSubstr((char *)data, "LOCATION");

	if(first>second){
		temp = first;
		first = second;
		second = temp;
		pos_location =1;
	}
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			for(j=i-16 ; j<i ; j++)
			{


				if(flag ==0 && j>first-2 &&((data[j]>=32 && data[j]<=128)||data[j]==10)){ //print first string

					if(data[j]=='\n' || data[j]=='\0'){
						first_str[k] = '\0';
						flag =1;
						k=0;
					}else{
						first_str[k] =(unsigned char) data[j];
						k++;
					}

				}
				if(flag ==1 && j>second-2 &&((data[j]>=32 && data[j]<=128)||data[j]==10)){ //print second string

					if(data[j]=='\n' || data[j]=='\0'){
						second_str[k]='\0';
						flag =2;
						k=0;
					}else{
						second_str[k] =(char) data[j];
						k++;
					}
				}

			}
		}
	}
	if(pos_location == 2){

		for(i=0; i<indloc; i++)
			if(strcmp(locations[i],second_str)==0)return;

	strcpy(locations[indloc],second_str);
	indloc++;
	}
	else{

		for(i=0; i<indloc; i++)
					if(strcmp(locations[i],first_str)==0)return;
		strcpy(locations[indloc],first_str);
		indloc++;
	}
	print_ip_header(data- header_size,Size+ header_size);
	fprintf(logfile, "\n%s\n%s\n",first_str,second_str);
}

void  INThandler(int sig)
{
	char c;

	if (logfile) {
		rewind(logfile);
		while((c=fgetc(logfile))!=EOF){
			printf("%c",c);
		}
		fclose(logfile);
	}
	exit(0);
}
