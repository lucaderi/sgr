/*
Come discusso ieri, lunedi prossimo non ci sara' lezione. Vi ho quindi chiesto se avete voglia di modificare il programma pcount.c (da rinominare in pbridge.c) e aggiungere un nuovo parametro (es. -o <interfaccia>) in modo che possa fare da bridge tra due interfacce di rete. Una volta che questa cosa e' stata fatta, potete anche aggiungere filtri sui pacchetti ricevuti in modo ad esempio di scartare certi pacchetti (es. su una certa porta o nome al dominio, o IP, quello che volete voi).
Se riuscite, invece di gestire la consegna di pbridge.c in modo aritgianale, sarebbe bene che vi leggiate questo https://github.com/lucaderi/sgr/blob/master/README.md e sotto una cartella chiamata 2026 che creerete, create una cartella col vostro cognome e inserire dentro pbridge.c. Per poter fare questo dovete farmi una pull request come descritto nel README sopra. Se avete domande scrivete pure.
*/



#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 65535
pcap_t  *pdA, *pdB;
volatile sig_atomic_t stop_bridge = 0;
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

void printHelp(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("Usage: pbridge [-h] -i <deviceA> -o <deviceB> [-f <filter>]\n");
    printf("-h            Print help\n");
    printf("-i <deviceA>  Input interface A\n");
    printf("-o <deviceB>  Output interface B\n");
    printf("-f <filter>   BPF filter applied on both interfaces\n");

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

void *bridge (void *arg) {
    pcap_t *device = (pcap_t*) arg;
    pcap_loop(device, -1, forwardPacket, (u_char *)device);
    return 0;
}

/* *************************************** */

void handle_sigint(int sig) {
    stop_bridge = 1;

    if (pdA != NULL) pcap_breakloop(pdA);
    if (pdB != NULL) pcap_breakloop(pdB);
}

/* *************************************** */


int main(int argc, char* argv[]) {
    char *deviceA = NULL, *deviceB = NULL, *bpfFilter = NULL;
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc, snaplen = DEFAULT_SNAPLEN;
    struct bpf_program fcodeA, fcodeB;
    pthread_t tA, tB;
    
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);


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
        printf("ERROR: '-o' device must be different than '-i' device\n");
        return -1;
    }

    printf("Bridging %s and %s\n", deviceA, deviceB);

    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1;
    pdA = pcap_open_live(deviceA, snaplen, promisc, 500, errbuf);
    if (pdA == NULL) {
        printf("pcap_open_live (input): %s\n", errbuf);
        return -1;
    }

    pdB = pcap_open_live(deviceB, snaplen, promisc, 500, errbuf);
    if (pdB == NULL) {
        printf("pcap_open_live (output): %s\n", errbuf);
        return -1;
    }

    if (pcap_setdirection(pdA, PCAP_D_IN) != 0) fprintf(stderr, "pcap_setdirection error on device: %s\n", deviceA);
    if (pcap_setdirection(pdB, PCAP_D_IN) != 0) fprintf(stderr, "pcap_setdirection error on device: %s\n", deviceB);

    if (bpfFilter != NULL) {
        if (pcap_compile(pdA, &fcodeA, bpfFilter, 1, 0xFFFFFF00) < 0 ||
            pcap_compile(pdB, &fcodeB, bpfFilter, 1, 0xFFFFFF00) < 0
           ) {
            printf("pcap_compile error: '%s'\n", pcap_geterr(pdA));
        } else {
            if (pcap_setfilter(pdA, &fcodeA) < 0 ||
                pcap_setfilter(pdB, &fcodeB) < 0
            ) {
                printf("pcap_setfilter error: '%s'\n", pcap_geterr(pdA));
            }
        }
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

    printf("\nBridge stopped\n");
    printf("Packets A -> B: %llu\n", pktsAtoB);
    printf("Packets B -> A: %llu\n", pktsBtoA);

    pcap_close(pdA);
    pcap_close(pdB);

    return(0);
}