/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pbridge.c -o pbridge -lpcap -pthread
 *
*/



#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define ALARM_SLEEP       3
#define DEFAULT_SNAPLEN 65535
pcap_t  *pdA, *pdB;
unsigned long long pktsAtoB = 0;
unsigned long long pktsBtoA = 0;

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

#include <pthread.h>
#include <bits/getopt_core.h>



typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef unsigned char u_char;

/* *************************************** */

int drop_privileges(const char *username) {
    struct passwd *pw = NULL;

    if (getgid() && getuid()) {
        fprintf(stderr, "privileges are not dropped as we're not superuser\n");
        return -1;
    }

    pw = getpwnam(username);

    if (pw == NULL) {
        username = "nobody";
        pw = getpwnam(username);
    }

    if (pw != NULL) {
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
            fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
            return -1;
        } else {
            fprintf(stderr, "user changed to %s\n", username);
        }
    } else {
        fprintf(stderr, "unable to locate user %s\n", username);
        return -1;
    }

    umask(0);
    return 0;
}


/* *************************************** */

void print_stats() {
    
    fprintf(stderr, "Actual Stats: %llu pkts from A to B.\n", pktsAtoB);
    fprintf(stderr, "Actual Stats: %llu pkts from B to A.\n", pktsBtoA);
    printf("\n");
}

/* *************************************** */

void printHelp(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("Usage: pbridge [-h] -i <deviceA> -o <deviceB> [-f <filter>]\n");
    printf("-h            Print help\n");
    printf("-i <deviceA>  Input interface A\n");
    printf("-o <deviceB>  Output interface B\n");
    printf("-f <filter>   BPF filter\n");

    if (pcap_findalldevs(&devpointer, errbuf) == 0) {
        int i = 0;

        printf("\nAvailable devices (-i):\n");
        while(devpointer) {
            const char *descr = devpointer->description;

            if (descr)
                printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
            else
                printf(" %d. %s\n", i++, devpointer->name);

            devpointer = devpointer->next;
        }
    }
}

/* *************************************** */

int send_packet(pcap_t *handle, const unsigned char *packet, int len) {
    if (pcap_inject(handle, packet, len) == -1) {
        fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
        return -1;
    }
    return 0;
}

/* *************************************** */

void forwardPacket(u_char *_deviceId,
                         const struct pcap_pkthdr *h,
                         const u_char *p) {
    
    if ((pcap_t*)_deviceId == pdA) {
        if (send_packet(pdB, p, h->caplen) == 0) pktsAtoB++;
    } else {
        if (send_packet(pdA, p, h->caplen) == 0) pktsBtoA++;
    }
}

/* *************************************** */

void *bridge (void *arg) {

    pcap_t *pd = (pcap_t*) arg;
    pcap_loop(pd, -1, forwardPacket, (u_char *)pd);
    return 0;
}


/* *************************************** */

pcap_t *open_live_interface(char *device, int snaplen, char *errbuf) {

    pcap_t *pd;
    /* hardcode: promisc=1, to_ms=500 */
    pd = pcap_open_live(device, snaplen, 1, 500, errbuf);
    if (pd == NULL) return NULL;

    /* Evita loop */
    if (pcap_setdirection(pd, PCAP_D_IN) != 0) return NULL;

    return pd;
}

/* *************************************** */

int set_filter(pcap_t *pd, const char *filter) {

    struct bpf_program fcode;

    if (pcap_compile(pd, &fcode, filter, 1, 0xFFFFFF00) < 0) return -1;
    else {
        if (pcap_setfilter(pd, &fcode) < 0) return -1;
    }

    return 0;

}

/* *************************************** */

void sigproc(int sig) {
    
    static int called = 0;
    fprintf(stderr, "Leaving...\n");
    if (called) return; else called = 1;

    if (pdA != NULL) pcap_breakloop(pdA);
    if (pdB != NULL) pcap_breakloop(pdB);
}

/* *************************************** */

void my_sigalarm(int sig) {
    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

int main(int argc, char* argv[]) {
    char *deviceA = NULL, *deviceB = NULL, *bpfFilter = NULL;
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen = DEFAULT_SNAPLEN;
    pthread_t tA, tB;
    
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);


    while((c = getopt(argc, argv, "hi:f:o:")) != '?') {
        if ((c == 255) || (c == (u_char)-1)) break;

        switch(c) {
        case 'h':
            printHelp();
            exit(0);
            break;

        case 'i':
            deviceA = strdup(optarg);
            break;
        case 'f':
            bpfFilter = strdup(optarg);
            break;

        case 'o':
            deviceB = strdup(optarg);
            break;
        }
    }

    if (geteuid() != 0) {
        printf("Please run this tool as superuser\n");
        return(-1);
    }

    if (deviceA == NULL) {
        printf("ERROR: Missing -i\n");
        printHelp();
        return(-1);
    }

    if (deviceB == NULL) {
        printf("ERROR: Missing -o\n");
        printHelp();
        return(-1);
    }

    if (strcmp(deviceA, deviceB) == 0) {
        printf("ERROR: '-o' device must be different than '-i' device.\n");
        return -1;
    }

    printf("Bridging %s and %s\n", deviceA, deviceB);

    /* Apre interfacce live e imposta direzione */
    pdA = open_live_interface(deviceA, snaplen, errbuf);
    pdB = open_live_interface(deviceB, snaplen, errbuf);
    if (pdA == NULL || pdB == NULL) {
        printf ("ERROR: open_live_interface %s\n", errbuf);
        return(-1);
    }

    /* Imposta filtri BPF */
    if (bpfFilter != NULL) {
        if (set_filter(pdA, bpfFilter) < 0) printf ("ERROR: Could not set bpf filters");  
        if (set_filter(pdB, bpfFilter) < 0)printf ("ERROR: Could not set bpf filters");
    }
    
    if (drop_privileges("nobody") < 0)
        return(-1);

    if (pthread_create(&tA, NULL, bridge, pdA) != 0 ||
        pthread_create(&tB, NULL, bridge, pdB) != 0) {
        printf("pthread_create error.\n");
        return 1;
    }

    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    printf("\nBridge stopped.\n");
    printf("Absolute Stats:\n");
    printf("Packets from A to B: %llu.\n", pktsAtoB);
    printf("Packets from B to A: %llu.\n", pktsBtoA);

    pcap_close(pdA);
    pcap_close(pdB);

    return(0);
}