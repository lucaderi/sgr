/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pcount.c -o pcount -lpcap
 *
*/

#define __FAVOR_BSD
#define _DEFAULT_SOURCE
//Aggiunte per evitare warning

#define _GNU_SOURCE
//strstr() mi dava segmentation fault, penso perché sui pacchetti non ho la terminazione in \0 allora uso memmem()

#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256

//Puntatori alle due interfacce
pcap_t *pd_in;
pcap_t *pd_out;

volatile int looping = 1;

int verbose = 0;
struct pcap_stat pcapStats;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

/* *************************************** */

int32_t gmt_to_local(time_t t) {
	int dt, dir;
	struct tm *gmt, *loc;
	struct tm sgmt;

	if (t == 0)
	  t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
	  (loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
	  dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

char* format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals)	{
	u_int a1 = ((u_long)val / 1000000000) % 1000;	
	u_int a = ((u_long)val / 1000000) % 1000;
	u_int b = ((u_long)val / 1000) % 1000;
	u_int c = (u_long)val % 1000;
	u_int d = (u_int)((val - (u_long)val)*100) % 100;

	if(add_decimals) {
	  if(val >= 1000000000) {
	    snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
	  } else if(val >= 1000000) {
	    snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
	  } else if(val >= 100000) {
	    snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
	  } else if(val >= 1000) {
	    snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
	  } else
	    snprintf(buf, buf_len, "%.2f", val);
	} else {
	  if(val >= 1000000000) {
	    snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
	  } else if(val >= 1000000) {
	    snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
	  } else if(val >= 100000) {
	    snprintf(buf, buf_len, "%u'%03u", b, c);
	  } else if(val >= 1000) {
	    snprintf(buf, buf_len, "%u'%03u", b, c);
	  } else
	    snprintf(buf, buf_len, "%u", (unsigned int)val);
	}

	return(buf);
}

/* *************************************** */

int drop_privileges(const char *username) {
	struct passwd *pw = NULL;

	if (getgid() && getuid()) {
	    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
	    return -1;
	}

	pw = getpwnam(username);

	if(pw == NULL) {
	    username = "nobody";
	    pw = getpwnam(username);
	}

	if(pw != NULL) {
	    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
	        fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
	    return -1;
	    }else{
	        fprintf(stderr, "user changed to %s\n", username);
	    }
	} else{
	    fprintf(stderr, "unable to locate user %s\n", username);
	    return -1;
	}

	umask(0);
	return 0;
}

/* *************************************** */
/*
 * The time difference in microseconds
 */
long delta_time (struct timeval * now,
	               struct timeval * before) {
	time_t delta_seconds;
	time_t delta_microseconds;

	/*
	 * compute delta in second, 1/10's and 1/1000's second units
	 */
	delta_seconds      = now -> tv_sec  - before -> tv_sec;
	delta_microseconds = now -> tv_usec - before -> tv_usec;

	if(delta_microseconds < 0) {
	  /* manually carry a one from the seconds field */
	    delta_microseconds += 1000000;  /* 1e6 */
	    -- delta_seconds;
	}
	return((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

/*
void print_stats() {
	struct pcap_stat pcapStat;
	struct timeval endTime;
	float deltaSec;
	static u_int64_t lastPkts = 0;
	u_int64_t diff;
	static struct timeval lastTime;
	char buf1[64], buf2[64];

	if(startTime.tv_sec == 0) {
	  lastTime.tv_sec = 0;
	  gettimeofday(&startTime, NULL);
	  return;
	}

	gettimeofday(&endTime, NULL);
	deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

	if(pcap_stats(pd, &pcapStat) >= 0) {
	  fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
	  fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

	  if(lastTime.tv_sec > 0) {
	    deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
	    diff = numPkts-lastPkts;
	    fprintf(stderr, "=========================\n"
	      "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
	      format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	      format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
	    lastPkts = numPkts;
	  }

	  fprintf(stderr, "=========================\n");
	}

	lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}
*/

/* ******************************** */

//Siccome non ho più pcap_loop cambio anche come catturo il ctrlc
void sigproc(int sig) {
  fprintf(stderr, "\nRicevuto segnale di interruzione. Chiusura in corso...\n");
  looping = 0; // Questo farà terminare il nostro futuro ciclo while
}

/* ******************************** */

/*
void my_sigalarm(int sig) {
	print_stats();
	alarm(ALARM_SLEEP);
	signal(SIGALRM, my_sigalarm);
}
*/

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const unsigned char *ep, char *buf) {
	u_int i, j;
	char *cp;

	cp = buf;
	if ((j = *ep >> 4) != 0)
	  *cp++ = hex[j];
	else
	  *cp++ = '0';

	*cp++ = hex[*ep++ & 0xf];

	for(i = 5; (int)--i >= 0;) {
	  *cp++ = ':';
	  if ((j = *ep >> 4) != 0)
	    *cp++ = hex[j];
	  else
	    *cp++ = '0';

	  *cp++ = hex[*ep++ & 0xf];
	}

	*cp = '\0';
	return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* __intoa(unsigned int addr, char* buf, u_short bufLen) {
	char *cp, *retStr;
	u_int byte;
	int n;

	cp = &buf[bufLen];
	*--cp = '\0';

	n = 4;
	do {
	  byte = addr & 0xff;
	  *--cp = byte % 10 + '0';
	  byte /= 10;
	  if (byte > 0) {
	    *--cp = byte % 10 + '0';
	    byte /= 10;
	    if (byte > 0)
	*--cp = byte + '0';
	  }
	  *--cp = '.';
	  addr >>= 8;
	} while (--n > 0);

	/* Convert the string to lowercase */
	retStr = (char*)(cp+1);

	return(retStr);
}

/* ************************************ */

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char* intoa(unsigned int addr) {
	return(__intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static inline char* in6toa(struct in6_addr addr6) {
	snprintf(buf, sizeof(buf),
	    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

	return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
	static char protoName[8];

	switch(proto) {
	case IPPROTO_TCP:  return("TCP");
	case IPPROTO_UDP:  return("UDP");
	case IPPROTO_ICMP: return("ICMP");
	default:
	    snprintf(protoName, sizeof(protoName), "%d", proto);
	    return(protoName);
	}
}

/* ****************************************************** */

static int32_t thiszone;


/* *************************************** */

void printHelp(void) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devpointer;

	printf("Usage: pbridge [-h] -i <device_in> -o <device_out> [-f <filter>] [-l <len>] [-v <1|2>]\n");  printf("-h               [Print help]\n");
	printf("-i <device|path> [Device name or file path]\n");
	printf("-f <filter>      [pcap filter]\n");
	printf("-l <len>         [Capture length]\n");
	printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");
    printf("-o <device>      [Output/Bridge Device name]\n");
    printf("-b <string>      [Blocco pacchetti contenenti questa stringa (es. nome dominio)]\n");

	if(pcap_findalldevs(&devpointer, errbuf) == 0) {
	int i = 0;

	printf("\nAvailable devices (-i):\n");
	while(devpointer) {
        const char *descr = devpointer->description;

        if(descr)
            printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
        else
            printf(" %d. %s\n", i++, devpointer->name);
        
        devpointer = devpointer->next;
        }
	}
}

/* *************************************** */

int main(int argc, char* argv[]) {
	char *device = NULL, *device_out = NULL, *bpfFilter = NULL, *blocked_domain = NULL;
	unsigned char c;
	char errbuf[PCAP_ERRBUF_SIZE];
	int promisc, snaplen = DEFAULT_SNAPLEN;
	struct bpf_program fcode;
	struct stat s;

	startTime.tv_sec = 0;
	thiszone = gmt_to_local(0);

	while((c = getopt(argc, argv, "hi:o:l:v:f:b:")) != '?') {
	    if((c == 255) || (c == (unsigned char)-1)) break;

	    switch(c) {
	    case 'h':
	        printHelp();
	        exit(0);
	        break;

	    case 'i':
	        device = strdup(optarg);
	        break;

	    case 'l':
	        snaplen = atoi(optarg);
	        break;

	    case 'v':
	        verbose = atoi(optarg);
	        break;

        case 'o':
            device_out = strdup(optarg);
            break;
        
        case 'b':
            blocked_domain = strdup(optarg);
            break;
        
	    case 'f':
	        bpfFilter = strdup(optarg);
	        break;
	    }
	}
	
	if(geteuid() != 0) {
	    printf("Please run this tool as superuser\n");
	    return(-1);
	}
	
	if(device == NULL) {
	    printf("ERROR: Missing -i\n");    
	    printHelp();
	    return(-1);  
	}

    //Facio il controllo anche sul secondo device
    if(device_out == NULL) {
        printf("ERROR: Missing -o (output device)\n");    
        printHelp();
        return(-1);
    }

	printf("Capturing from %s\n", device);


	/* hardcode: promisc=1, to_ms=500 */
	promisc = 1;
	if((pd_in = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
	    printf("pcap_open_live: %s\n", errbuf);
	    return(-1);
	}

    //Uguale apro la seconda interfaccia
    if((pd_out = pcap_open_live(device_out, snaplen, promisc, 500, errbuf)) == NULL) {
        printf("pcap_open_live error on %s: %s\n", device_out, errbuf);
        return(-1);
    }
    
    printf("Bridging attivo: %s <--> %s\n", device, device_out);

	//Chiesto a Gemini mi ha suggerito di mettere queste due righe
	//evito loop/eco
	pcap_setdirection(pd_in, PCAP_D_IN);
	pcap_setdirection(pd_out, PCAP_D_IN);
	
    /*
	if(bpfFilter != NULL) {
	  if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
	    printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
	  } else {
	    if(pcap_setfilter(pd, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
	    }
	  }
	}
    */

    if(bpfFilter != NULL) {
    
        if(pcap_compile(pd_in, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0){
        printf("pcap_compile error: '%s'\n", pcap_geterr(pd_in));

        } else{
            //Filtro a interfaccia 1
            if(pcap_setfilter(pd_in, &fcode) < 0){
                printf("pcap_setfilter error on %s: '%s'\n", device, pcap_geterr(pd_in));
            }
            //Uguale a 2
            if(pcap_setfilter(pd_out, &fcode) < 0){
                printf("pcap_setfilter error on %s: '%s'\n", device_out, pcap_geterr(pd_out));
            }
        }
    }

    //I file ds per select
    int fd_in = pcap_get_selectable_fd(pd_in);
    int fd_out = pcap_get_selectable_fd(pd_out);

    if(fd_in < 0 || fd_out < 0){
        printf("Errore su select()\n");
        return(-1);
    }

    int max_fd = (fd_in > fd_out) ? fd_in : fd_out;



	
	if(drop_privileges("nobody") < 0)
	  return(-1);
	

	signal(SIGINT, sigproc);
	signal(SIGTERM, sigproc);

    /*
	if(!verbose) {
	    signal(SIGALRM, my_sigalarm);
	    alarm(ALARM_SLEEP);
	}
    */

    /**************************************************************** */
    
    printf("\nInoltro pacchetti...\n");


	size_t blocked_len = 0;
	if(blocked_domain != NULL){
		blocked_len = strlen(blocked_domain);
	}

    while(looping){

        fd_set readfds; //È una specie di bitmask per i fileds
        struct timeval tv;
        struct pcap_pkthdr* header; //Dove metto i dait
        const unsigned char* pkt_data;
        int res;
        

        FD_ZERO(&readfds);  //svuoto
        FD_SET(fd_in, &readfds);
        FD_SET(fd_out, &readfds);

        //Mi metto un timer di 1 secondo per la select
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        //Passo fino a dove controllare e i descrittori da monitorare
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);

        if(ret < 0){
            if (errno == EINTR) continue;   //ctrlc
            perror("Errore select");
            break;
        } else if(ret == 0){
            //Scaduto timeout
            continue;
        }

        if(FD_ISSET(fd_in, &readfds)){  //controllo se fd_in è settato	
            res = pcap_next_ex(pd_in, &header, &pkt_data);
            
            //invio all'altra interfaccia
            if(res == 1){

				int scarta = 0;	//prima usavo continue, ma in quel caso mi avrebbe potuto scartare un pacchetto dall'altro latoì
                //Filtro manuale
                if(blocked_domain != NULL){
                    //anche se inefficiente cerco la stringa all'interno dei byte del pacchetto
                    if(memmem(pkt_data, header->caplen, blocked_domain, blocked_len) != NULL){
						if(verbose == 1){
                        	printf("Pacchetto scartato contentete '%s' da dal device %s\n", blocked_domain, device);
                    	}
						scarta = 1;
					}
                }
				if(!scarta){
					if((pcap_sendpacket(pd_out, pkt_data, header->caplen)) != 0){
						fprintf(stderr, "Errore invio su %s: %s", device_out, pcap_geterr(pd_out));
					} else if(verbose == 1){
						printf("Inoltrato pacchetto da %s a %s di %d bytes\n", device, device_out, header->len);
					}
				}
            }
        }
        //Identico per pacchetto dall'altro
        if(FD_ISSET(fd_out, &readfds)){
            res = pcap_next_ex(pd_out, &header, &pkt_data);

            if(res == 1){

				int scarta = 0;
                //Filtro manuale
                if(blocked_domain != NULL){
                    //anche se inefficiente cerco la stringa all'interno dei byte del pacchetto
                    if(memmem(pkt_data, header->caplen, blocked_domain, blocked_len) != NULL){
						if(verbose == 1){
                        	printf("Pacchetto scartato contentete '%s' da dal device %s\n", blocked_domain, device);
                    	}
                    	scarta = 1;
					}
                }
				if(!scarta){
					if((pcap_sendpacket(pd_in, pkt_data, header->caplen))!= 0){
						fprintf(stderr, "Errore invio su %s: %s", device, pcap_geterr(pd_in));
					} else if(verbose == 1){
						printf("Inoltrato pacchetto da %s a %s di %d bytes\n", device_out, device, header->len);
					}
				}
            }
        }
    }

    printf("Uscita dal bridge\n");


    /*********************************************** */

	//print_stats();

	pcap_close(pd_in);
	pcap_close(pd_out);
	
	return(0);
}
