/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc pbridge.c -o pbridge -lpcap
 *
*/

#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>


#define DEFAULT_SNAPLEN 256
pcap_t* pd;
pcap_t* pd2;

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <poll.h>


static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
volatile int running = 1;

/* *************************************** */

char* format_numbers(double val, char* buf, u_int buf_len, u_int8_t add_decimals)
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

int drop_privileges(const char* username)
{
    struct passwd* pw = NULL;

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
long delta_time(struct timeval* now,
                struct timeval* before)
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
{
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
    // flag necessario per far si che sigproc sia chiamata una sola volta anche dopo più segnali di terminazione
    static int called = 0;

    fprintf(stderr, "Leaving...\n");
    if (called) return;
    else called = 1;

    running = 0;
    pcap_breakloop(pd);
    if (pd2 != NULL) pcap_breakloop(pd2);
}


/* ****************************************************** */


void ProcessPacket(u_char* dest,
                         const struct pcap_pkthdr* h,
                         const u_char* p)
{
    if (numPkts == 0) gettimeofday(&startTime, NULL);       // inizio a registrare timestamp dal primo pacchetto
    numPkts++, numBytes += h->len;

    int retries = 3;
    while (retries-- > 0) {
        if ( pcap_sendpacket((pcap_t *) dest, p, (int) h->caplen) == 0) break;       // forwarding all'altra interfaccia
        if (retries >0) usleep(1000);   // sleep di 1ms in caso di errori di invio
        else fprintf(stderr, "pcap_sendpacket() failed after retries: %s\n", pcap_geterr((pcap_t *) dest));
    }
}

/* *************************************** */


void printHelp(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devpointer;

    printf("Usage: pbridge [-h] -i <device|path> -o <device|path>\n");
    printf("-h               [Print help]\n");
    printf("-i <device|path> [Device name or file path]\n");
    printf("-o <device>      [Output device name]\n");

    if (pcap_findalldevs(&devpointer, errbuf) == 0)
    {
        int i = 0;

        printf("\nAvailable devices (-i):\n");
        while (devpointer)
        {
            const char* descr = devpointer->description;

            if (descr)
                printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
            else
                printf(" %d. %s\n", i++, devpointer->name);

            devpointer = devpointer->next;
        }
    }
}

/* *************************************** */

int main(int argc, char* argv[])
{
    char *device = NULL, *device2 = NULL;
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE], errbuf2[PCAP_ERRBUF_SIZE];
    const int snaplen = DEFAULT_SNAPLEN;

    startTime.tv_sec = 0;

    while ((c = getopt(argc, argv, "hi:o:")) != '?')
    {
        if ((c == 255) || (c == (u_char)-1)) break;
        switch (c) {
            case 'h':
                printHelp();
                exit(0);

            case 'i':
                device = strdup(optarg);
                break;

            case 'o':
                device2 = strdup(optarg);
                break;
            default:
                printHelp();
                exit(0);;
        }

    }

    if (geteuid() != 0)
    {
        printf("Please run this tool as superuser\n");
        return (-1);
    }

    if (device == NULL)
    {
        printf("ERROR: Missing -i\n");
        printHelp();
        return (-1);
    }
	if (device2 == NULL) {
	    printf("ERROR: Missing -o\n");
	    printHelp();
	    return (-1);
	}


    printf("Bridging: %s and %s\n", device, device2);

    const int promisc = 1;
    if ((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL)
    {
        printf("pcap_open_live: %s\n", errbuf);
        return (-1);
    }
    if ((pd2 = pcap_open_live(device2, snaplen, promisc, 500, errbuf2)) == NULL)
    {
        printf("pcap_open_live: %s\n", errbuf2);
        pcap_close(pd);
        return (-1);
    }


    if (drop_privileges("nobody") < 0)
        return (-1);

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    if (pcap_setdirection(pd,  PCAP_D_IN)<0) fprintf(stderr,"pcap_setdirection: %s\n",pcap_geterr(pd));
    if (pcap_setdirection(pd2, PCAP_D_IN)<0) fprintf(stderr,"pcap_setdirection: %s\n",pcap_geterr(pd2));


    // poll
    const int nfds = 2;
    struct pollfd fds[nfds];
    fds[0].fd = pcap_get_selectable_fd(pd);
    fds[1].fd = pcap_get_selectable_fd(pd2);
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;
    while (running) {
        const int ret = poll(fds, nfds, 1000);
        if (ret < 0)
        {
            if (errno == EINTR) continue;
            fprintf(stderr, "poll error: %s\n", strerror(errno));
            break;
        }
        if (fds[0].revents & POLLIN)
            pcap_dispatch(pd, -1, ProcessPacket, (u_char*)pd2);
        if (fds[1].revents & POLLIN)
            pcap_dispatch(pd2, -1, ProcessPacket, (u_char*)pd);

    }

    print_stats();
    pcap_close(pd);
    pcap_close(pd2);

    return (0);
}