#define APP_NAME		"Citter"
#define APP_DESC		"A sniffer example using libpcap to analyze the comunication frequency of TCP streams."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include "gnuplot_i.h"
#include "time_tools.h"
#include "jitter_data.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

extern anomaly_list *a_list;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

void print_graphic(){
    printf("Insert ip source and ip destination, Example: 'Ip-10.0.2.15-99.86.47.11\n");
    char file_name[40];
    int i=0;
    FILE *f;
    char aux[121], *token;
    double d[40], index[40];
    gnuplot_ctrl * h;
    h = gnuplot_init();

    scanf("%s", file_name);
    strcat(file_name, ".txt");
    f = fopen (file_name,"r");
    if(f == NULL) {
        perror("Error opening file");
        return;
    }
    gnuplot_setstyle(h, "lines");
    while(fgets(aux, 120, f) != NULL) {
        token = strtok(aux, " ");
        d[i] = i;

        token = strtok(NULL, " ");
        index[i] = atof(token);
        printf("time: %le(double) or %d(int), jiter: %le(double) or %d(int)\n", d[i], (int)d[i], index[i], (int)index[i]);
        i++;
    }


    gnuplot_cmd(h, "set term x11 persist");
    strcat(file_name, ": Jitter Comunication");
    gnuplot_plot_xy(h, d, index, i-1,file_name);
    gnuplot_close(h);
}




void print_app_banner(void){
	printf("%s - %s\n", APP_NAME, APP_DESC);
return;
}

void print_app_usage(void) {
	printf("Usage: %s [packet_number]\n", APP_NAME);
	printf("\n");
	printf("Argument:\n");
	printf("(optional)   packet_number       Capture the next <packet_number> packets.\n");
	printf("\nIf no packet_number is provided, this process will start sniffing non-stop.\n");
	printf("In both cases until it can be correctly stopped sending a SIGINT interruption to this process.\n");
return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	//const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */

	int size_ip;
	int size_tcp;

	printf("Sniffed %d packets.\n", count);
	count++;

	/* define ethernet header */
	//ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	char *ip_src_string = malloc(sizeof(char) * 50);
	char *ip_dst_string = malloc(sizeof(char) * 50);
	strcpy(ip_src_string, inet_ntoa(ip->ip_src));
	strcpy(ip_dst_string, inet_ntoa(ip->ip_dst));
	int  src_port = ntohs(tcp->th_sport);
	int  dst_port = ntohs(tcp->th_dport);
	struct timespec now = update_timespec();

	char *stream_name = (char *) malloc(sizeof(char) * 60);
	sprintf(stream_name, "Ip-%s-%s", ip_src_string, ip_dst_string);
	add_record(stream_name, timespec_to_millis(now), src_port, dst_port);

return;
}

pcap_t *handle = NULL; /*packet capture handle*/

void sig_handler(int signo){
		//This routine is safe to use inside a signal handler on UNIX or a console control handler on Windows,
		//as it merely sets a flag that is checked within the loop.
		if(handle != NULL)
			pcap_breakloop(handle);

		return;
}

void print_capture_info(char *device, int num_packets, char *filter_exp){
	if(device == NULL || filter_exp == NULL){
		fprintf(stderr, "Method: print_capture_info    Error: NULL device or filter_exp string.  (unexpected arguments)\n");
	}
	printf("Device:            %s\n", device);
	if(num_packets > 0)
		printf("Number of packets: %d\n", num_packets);
	else
		printf("Number of packets: sniffing until SIGINT has been received.\n");

	printf("Filter expression: %s\n", filter_exp);

	return;
}

int main(int argc, char **argv) {
	if(signal(SIGINT, sig_handler) == SIG_ERR){
			fprintf(stderr, "\nCan't catch SIGINT\n");
			exit(EXIT_FAILURE);
	}

    pcap_if_t *dev_list;

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	char filter_exp[] = "tcp[tcpflags] & (tcp-syn) != 0";		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets;			/* number of packets to capture */
    struct timespec now = update_timespec();
    long int start = timespec_to_millis(now);

	print_app_banner();

	/* check for capture packets number on command-line */
	switch(argc){
		case 1:
			num_packets = 0;
			break;
		case 2:
			num_packets = atoi(argv[1]);
			break;
		default:
			fprintf(stderr, "error: unrecognized command-line arguments\n\n");
			print_app_usage();
			exit(EXIT_FAILURE);
	}

  if(pcap_findalldevs(&dev_list, errbuf) == PCAP_ERROR){
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
  }

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev_list->name, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev_list->name, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	print_capture_info(dev_list->name, num_packets, filter_exp);

	/* open capture device */
  handle = pcap_create(dev_list->name, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev_list->name, errbuf);
		exit(EXIT_FAILURE);
	}

  if(pcap_set_timeout( handle, 1 ) != 0){
		fprintf(stderr, "Unable to configure timeout.\n");
    exit(EXIT_FAILURE);
  }

  if( pcap_set_immediate_mode( handle, 1 ) != 0 ){
		fprintf(stderr, "Unable to configure immediate mode.\n");
    exit(EXIT_FAILURE);
	}

  // Activate packet capture handle to look at packets on the network
  int activateStatus = pcap_activate(handle);
  if( activateStatus < 0 ){
    fprintf(stderr, "Activate failed\n");
    exit(EXIT_FAILURE);
  }

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev_list->name);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	initialize_map();
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n\n");
    save_map(start);
	print_map();
    print_anomaly_list();
    int comando = 1;

    while(comando != 0 ){
        printf("\n******USER MENU******\n 0: exit\n 1: draw jitter graphic\n 2: print anomaly list\n 3: print connections list\n");
        scanf("%d", &comando);

        switch (comando) {
            case 0:
                return 0;
                break;
            case 1:
                print_graphic();
                break;
            case 2:
                print_anomaly_list();
                break;
            case 3:
                print_map();
                break;
            default:
                printf("Insert correct command\n");
                break;
        }
    }

    return 0;
}
