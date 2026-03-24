/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pcount.c -o pcount -lpcap
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
#include <poll.h>

#define ALARM_SLEEP 1
#define DEFAULT_SNAPLEN 256
pcap_t *pd;
pcap_t *pd_out; /* AGGIUNTA: handle per l'invio dei pacchetti */
int verbose = 0;
int volatile finished = 0; /*AGGIUNTA variabile chiusura */
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
#include <net/ethernet.h> /* the L2 protocols */

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
pcap_dumper_t *dumper = NULL;

/*AGGIUNTA: definizione di una struct che contenga l'input e la destinazione*/
struct bridge_info {
    pcap_t *pd_in;
    pcap_t *pd_out;
};

/* *************************************** */

int32_t gmt_to_local(time_t t)
{
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

char *format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals)
{
    u_int a1 = ((u_long)val / 1000000000) % 1000;
    u_int a = ((u_long)val / 1000000) % 1000;
    u_int b = ((u_long)val / 1000) % 1000;
    u_int c = (u_long)val % 1000;
    u_int d = (u_int)((val - (u_long)val) * 100) % 100;

    if (add_decimals)
    {
        if (val >= 1000000000)
        {
            snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
        }
        else if (val >= 1000000)
        {
            snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
        }
        else if (val >= 100000)
        {
            snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
        }
        else if (val >= 1000)
        {
            snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
        }
        else
            snprintf(buf, buf_len, "%.2f", val);
    }
    else
    {
        if (val >= 1000000000)
        {
            snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
        }
        else if (val >= 1000000)
        {
            snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
        }
        else if (val >= 100000)
        {
            snprintf(buf, buf_len, "%u'%03u", b, c);
        }
        else if (val >= 1000)
        {
            snprintf(buf, buf_len, "%u'%03u", b, c);
        }
        else
            snprintf(buf, buf_len, "%u", (unsigned int)val);
    }

    return (buf);
}

/* *************************************** */

int drop_privileges(const char *username)
{ // funzione per riprendere i privilegi di nobody
    struct passwd *pw = NULL;

    if (getgid() && getuid())
    {
        fprintf(stderr, "privileges are not dropped as we're not superuser\n");
        return -1;
    }

    pw = getpwnam(username);

    if (pw == NULL)
    {
        username = "nobody";
        pw = getpwnam(username);
    }

    if (pw != NULL)
    {
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
        {
            fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
            return -1;
        }
        else
        {
            fprintf(stderr, "user changed to %s\n", username);
        }
    }
    else
    {
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
long delta_time(struct timeval *now,
                struct timeval *before)
{
    time_t delta_seconds;
    time_t delta_microseconds;

    /*
     * compute delta in second, 1/10's and 1/1000's second units
     */
    delta_seconds = now->tv_sec - before->tv_sec;
    delta_microseconds = now->tv_usec - before->tv_usec;

    if (delta_microseconds < 0)
    {
        /* manually carry a one from the seconds field */
        delta_microseconds += 1000000; /* 1e6 */
        --delta_seconds;
    }
    return ((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

void print_stats()
{ // stampa delle statistiche se richiesta con verbose
    struct pcap_stat pcapStat;
    struct timeval endTime;
    float deltaSec;
    static u_int64_t lastPkts = 0;
    u_int64_t diff;
    static struct timeval lastTime;
    char buf1[64], buf2[64];

    if (startTime.tv_sec == 0)
    {
        lastTime.tv_sec = 0;
        gettimeofday(&startTime, NULL);
        return;
    }

    gettimeofday(&endTime, NULL);
    deltaSec = (double)delta_time(&endTime, &startTime) / 1000000;

    if (pcap_stats(pd, &pcapStat) >= 0)
    {
        fprintf(stderr, "=========================\n"
                        "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
                        "Total Pkts=%u/Dropped=%.1f %%\n",
                pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_recv - pcapStat.ps_drop,
                pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop * 100) / (double)pcapStat.ps_recv);
        fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
                numPkts, (double)numPkts / deltaSec,
                numBytes, (double)8 * numBytes / (double)(deltaSec * 1000000));

        if (lastTime.tv_sec > 0)
        {
            deltaSec = (double)delta_time(&endTime, &lastTime) / 1000000;
            diff = numPkts - lastPkts;
            fprintf(stderr, "=========================\n"
                            "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
                    format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec * 1000,
                    format_numbers(((double)diff / (double)(deltaSec)), buf2, sizeof(buf2), 1));
            lastPkts = numPkts;
        }

        fprintf(stderr, "=========================\n");
    }

    lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig)
{
    static int called = 0;

    fprintf(stderr, "Leaving...\n");
    if (called)
        return;
    else
        called = 1;

    finished = 1;
}

/* ******************************** */

void my_sigalarm(int sig)
{
    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char *etheraddr_string(const u_char *ep, char *buf)
{
    u_int i, j;
    char *cp;

    cp = buf;
    if ((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for (i = 5; (int)--i >= 0;)
    {
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
char *__intoa(unsigned int addr, char *buf, u_short bufLen)
{
    char *cp, *retStr;
    u_int byte;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';

    n = 4;
    do
    {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0)
        {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0)
                *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    /* Convert the string to lowercase */
    retStr = (char *)(cp + 1);

    return (retStr);
}

/* ************************************ */

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char *intoa(unsigned int addr)
{
    return (__intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static inline char *in6toa(struct in6_addr addr6)
{
    snprintf(buf, sizeof(buf),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
             addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
             addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
             addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
             addr6.s6_addr[15]);

    return (buf);
}

/* ****************************************************** */

char *proto2str(u_short proto)
{
    static char protoName[8];

    switch (proto)
    {
    case IPPROTO_TCP:
        return ("TCP");
    case IPPROTO_UDP:
        return ("UDP");
    case IPPROTO_ICMP:
        return ("ICMP");
    default:
        snprintf(protoName, sizeof(protoName), "%d", proto);
        return (protoName);
    }
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(u_char *_deviceId,
                         const struct pcap_pkthdr *h,
                         const u_char *p)
{

    // printf("pcap_sendpacket returned %d\n", pcap_sendpacket(pd, p, h->caplen));

    struct bridge_info *bridge = (struct bridge_info *)_deviceId; /*AGGIUNTA: cast del deviceId in ingresso alla funzione di callback in modo da poter accedere agli handle di input e output del bridge*/

    /*AGGIUNTA base invio al'output device*/
    if (bridge->pd_out) /*AGGIUNTA: controllo che l'handle di output del bridge sia valido prima di inviare il pacchetto*/
    {
        if (pcap_inject(bridge->pd_out, p, h->caplen) == -1)
        {
            fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(bridge->pd_out));
            exit(1);
        }
    }
    if (dumper)
        pcap_dump((u_char *)dumper, (struct pcap_pkthdr *)h, p);

    if (verbose)
    {
        struct ether_header ehdr;
        u_short eth_type, vlan_id;
        char buf1[32], buf2[32];
        struct ip ip;
        struct ip6_hdr ip6;

        int s = (h->ts.tv_sec + thiszone) % 86400;

        printf("%02d:%02d:%02d.%06u ",
               s / 3600, (s % 3600) / 60, s % 60,
               (unsigned)h->ts.tv_usec);

        memcpy(&ehdr, p, sizeof(struct ether_header));
        eth_type = ntohs(ehdr.ether_type);
        printf("[%s -> %s] ",
               etheraddr_string(ehdr.ether_shost, buf1),
               etheraddr_string(ehdr.ether_dhost, buf2));

        if (eth_type == 0x8100)
        {
            vlan_id = (p[14] & 15) * 256 + p[15];
            eth_type = (p[16]) * 256 + p[17];
            printf("[vlan %u] ", vlan_id);
            p += 4;
        }
        if (eth_type == 0x0800)
        {
            memcpy(&ip, p + sizeof(ehdr), sizeof(struct ip));
            printf("[%s]", proto2str(ip.ip_p));
            printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
            printf("-> %s] ", intoa(ntohl(ip.ip_dst.s_addr)));
        }
        else if (eth_type == 0x86DD)
        {
            memcpy(&ip6, p + sizeof(ehdr), sizeof(struct ip6_hdr));
            printf("[%s ", in6toa(ip6.ip6_src));
            printf("-> %s] ", in6toa(ip6.ip6_dst));
        }
        else if (eth_type == 0x0806)
            printf("[ARP]");
        else
            printf("[eth_type=0x%04X]", eth_type);

        printf("[caplen=%u][len=%u]\n", h->caplen, h->len);
    }

    if (numPkts == 0)
        gettimeofday(&startTime, NULL);
    numPkts++, numBytes += h->len;

    if (verbose == 2)
    {
        int i;

        for (i = 0; i < h->caplen; i++)
            printf("%02X ", p[i]);
        printf("\n");
    }
}

/* *************************************** */

void printHelp(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("Usage: pcount [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
    printf("-h               [Print help]\n");
    printf("-i <device|path> [Device name or file path]\n");
    printf("-f <filter>      [pcap filter]\n");
    printf("-w <path>        [pcap write file]\n");
    printf("-l <len>         [Capture length]\n");
    printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");
    /* AGGIUNTA */
    printf("-o <device>     [Output device for pcap_sendpacket]\n");


    if (pcap_findalldevs(&devpointer, errbuf) == 0)
    {
        int i = 0;

        printf("\nAvailable devices (-i):\n");
        while (devpointer)
        {
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

int main(int argc, char *argv[])
{
    char *device1 = NULL, *bpfFilter = NULL; 
    char *device2 = NULL; /* AGGIUNTA*/ // preparo filtro e dispositivo per fare il bridge dei pacchetti
    struct bridge_info bridge1 = {0}, bridge2 = {0}; /*AGGIUNTA: due struct per gestire input e output del bridge*/
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc = 1, snaplen = DEFAULT_SNAPLEN; 
    struct bpf_program fcode;
    struct stat s1, s2;
    int device1_is_file = 0, device2_is_file = 0; /*AGGIUNTA: flag per capire se device1/device2 sono file oppure interfacce live*/

    startTime.tv_sec = 0;
    thiszone = gmt_to_local(0);

    while ((c = getopt(argc, argv, "hi:l:v:f:w:o:")) != '?') /*AGGIUNTA*/
    {
        if ((c == 255) || (c == (u_char)-1))
            break;

        switch (c)
        {
        case 'h': // help per capire come funziona il programma
            printHelp();
            exit(0);
            break;

        case 'i': // setto l'interfaccia di rete
            device1 = strdup(optarg);
            break;

        case 'l': // metto lunghezza personalizzata dei pacchetti in byte
            snaplen = atoi(optarg);
            break;

        case 'v': // 1 per info pacchetto 2 per anche il contenuto
            verbose = atoi(optarg);
            break;

        case 'w': // dove salvare i contenuti catturati
            dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), optarg);
            if (dumper == NULL)
            {
                printf("Unable to open dump file %s\n", optarg);
                return (-1);
            }
            break;

        case 'f': // salvataggio filtro bpf
            bpfFilter = strdup(optarg);
            break;

        /*AGGIUNTA*/
        case 'o': // setto l'interfaccia di rete su cui inviare i con inject della libpcap
            device2 = strdup(optarg);
            break;
        }
    }
    
    if (geteuid() != 0)
    {
        printf("Please run this tool as superuser\n");
        return (-1);
    }

    if (device1 == NULL)
    {
        printf("ERROR: Missing -i\n");
        printHelp();
        return (-1);
    }

    printf("Capturing from %s\n", device1);

    /*AGGIUNTA: controllo se device1 e device2 sono file esistenti oppure interfacce live*/
    if (stat(device1, &s1) == 0)
        device1_is_file = 1;

    if (device2 != NULL && stat(device2, &s2) == 0)
        device2_is_file = 1;

    if (device2 != NULL && device1_is_file && device2_is_file) /*AGGIUNTA: se entrambi i dispositivi specificati sono file esistenti, non posso fare il bridge perché non ho un'interfaccia di output per inviare i pacchetti catturati, quindi esco con un errore*/
    {
        printf("Both device1 and device2 are files. Bridge cannot be established.\n");
        return -1;
    }

    // definizione dei bridge tra le interfacce

    if (device1_is_file)
    {
        if ((pd = pcap_open_offline(device1, errbuf)) == NULL)
        {
            printf("pcap_open_offline: %s\n", errbuf);
            return -1;
        }
        bridge1.pd_in = pd; /*AGGIUNTA: setto l'handle di input del bridge1 con quello della cattura offline*/
    }
    else
    {
        if ((pd = pcap_open_live(device1, snaplen, promisc, 500, errbuf)) == NULL)
        {
            printf("pcap_open_live: %s\n", errbuf);
            return -1;
        }
        bridge1.pd_in = pd; /*AGGIUNTA: setto l'handle di input del bridge1 con quello della cattura live*/
    }

    if (device2 != NULL) /*AGGIUNTA: se è stato specificato un secondo dispositivo, lo tratto come interfaccia di output live del bridge/replay*/
    {
        if (device2_is_file) /*AGGIUNTA: device2 non può essere usato come output del bridge se è un file offline*/
        {
            printf("device2 is a file. Output for bridge/replay must be a live interface.\n");
            return -1;
        }

        printf("Capturing from %s\n", device2);
        printf("Starting bridge between %s and %s\n", device1, device2);

        if ((pd_out = pcap_open_live(device2, snaplen, promisc, 500, errbuf)) == NULL)/*AGGIUNTA interfaccia di output per il bridge dei pacchetti*/
        { 
            printf("pcap_open_live: %s\n", errbuf);
            return -1;
        }

        bridge1.pd_out = pd_out; //setto l'handle di output del bridge1 con quello della cattura live

        if (!device1_is_file) /*AGGIUNTA: se anche device1 è live, abilito il bridge bidirezionale tra le due interfacce*/
        {
            bridge2.pd_in = pd_out; //setto l'handle di input del bridge2 con quello della cattura live
            bridge2.pd_out = pd; //setto l'handle di output del bridge2 con quello della prima interfaccia live
        }
    }

    if (bpfFilter != NULL)
    {
        if (pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0)
        {
            printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
        }
        else
        {
            if (pcap_setfilter(pd, &fcode) < 0)
            { // applicazione del filtro se la compilazione è andata bene
                printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
            }
        }
    }

    if (bpfFilter != NULL && pd_out != NULL) /*AGGIUNTA: se è stato specificato un filtro e ho un'interfaccia di output per il bridge, applico lo stesso filtro anche su quella*/
    {
        if (pcap_compile(pd_out, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0)
        {
            printf("pcap_compile error: '%s'\n", pcap_geterr(pd_out));
        }
        else
        {
            if (pcap_setfilter(pd_out, &fcode) < 0)
            { // applicazione del filtro se la compilazione è andata bene
                printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd_out));
            }
        }
    }

    if (drop_privileges("nobody") < 0) 
        return (-1);

    signal(SIGINT, sigproc);  // segnali di kill del processo
    signal(SIGTERM, sigproc); // interrompe il ciclo di cattura in modo pulito

    if (!verbose)
    {
        signal(SIGALRM, my_sigalarm); // associazione a sigallarm al mio signal handler per la getione
        alarm(ALARM_SLEEP);           // costante definita sopra aspetto un secondo e poi fermo temporaneamente l'eseuzione stampando le statistiche sull'aquisizione che ho avuto fino ad adesso
    }

    // implementazionde della logica di cattura dalle 2 interfacce e invio dei pacchetti catturati da una all'altra

    if (device1_is_file) /*AGGIUNTA: se la sorgente è un file offline, non uso poll ma leggo tutti i pacchetti dal file e li invio eventualmente all'interfaccia live di output*/
    {
        int rc;

        rc = pcap_dispatch(pd, -1, dummyProcesssPacket, (u_char *)&bridge1);
        if (rc < 0)
        {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(pd));
        }
    }
    else
    {
        int ret1, ret2, nfds = 1; //filedescriptor per la cattura delle interfacce di input e output del bridge
        struct pollfd fds[2]; // array di struct pollfd per monitorare i filedescriptor delle interfacce di input e output del bridge
        int count; // numero degli eventi di lettura disponibili sui filedescriptor monitorati

        ret1 = pcap_get_selectable_fd(pd);

        if (ret1 < 0)
        {
            fprintf(stderr, "pcap_get_selectable_fd() not supported on input interface\n");
            return (-1);
        }

        fds[0].fd = ret1; // registro il filedescriptor
        fds[0].events = POLLIN; // setto l'evento di interesse per la lettura dei pacchetti
        fds[0].revents = 0; // azzero i revents per evitare problemi di lettura

        if (pd_out != NULL && !device1_is_file) //registro anche il filedescriptor della seconda interfaccia solo se sto facendo un bridge live-live
        {   
            ret2 = pcap_get_selectable_fd(pd_out);
            if (ret2 < 0)
            {
                fprintf(stderr, "pcap_get_selectable_fd() not supported on output interface\n");
                return (-1);
            }

            fds[1].fd = ret2;
            fds[1].events = POLLIN;
            fds[1].revents = 0;
            nfds = 2; // setto il numero di filedescriptor da monitorare a 2 se ho aperto anche la seconda interfaccia live del bridge
        }

        while (finished != 1)
        {
            count = poll(fds, nfds, -1); // attendo eventi di lettura su entrambi i filedescriptor
            if (count < 0)
            {
                if (errno == EINTR) // se il poll è interrotto da un segnale, continuo ad aspettare
                    continue;
                fprintf(stderr, "poll error: %s\n", strerror(errno));
                perror("poll");
                break;
            }

            if (count == 0) // se il poll ritorna senza eventi, continuo ad aspettare
                continue;

            if (fds[0].revents & POLLIN) // se ci sono pacchetti da leggere sull'interfaccia di input del bridge, li leggo e li invio sull'interfaccia di output del bridge
            {
                count = pcap_dispatch(pd, -1, dummyProcesssPacket, (u_char *)&bridge1); // utilizzo la funzione di callback per processare i pacchetti catturati e inviarli sull'interfaccia di output del bridge
                if (count < 0)
                {
                    fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(pd));
                    break;
                }
            }

            if (nfds == 2 && (fds[1].revents & POLLIN)) // se sto facendo bridge bidirezionale live-live, processo anche i pacchetti catturati sulla seconda interfaccia
            { 
                count = pcap_dispatch(pd_out, -1, dummyProcesssPacket, (u_char *)&bridge2); 
                if (count < 0)
                {
                    fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(pd_out));
                    break;
                }
            }
        }
    }

    print_stats(); // riprinto a chiusura le statistiche

    pcap_close(pd); // chiudo la lettura e l'interfaccia di rete da cui stavo leggendo o chiudo il filedescriptor
    if (pd_out)
        pcap_close(pd_out); /*AGGIUNTA: chiudo anche l'handle di output del bridge se è stato aperto*/
    if (dumper)
        pcap_dump_close(dumper);

    return (0);
}