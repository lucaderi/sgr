#include <pcap/pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <stdlib.h>
#include <stddef.h>
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
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
//#include <netinet/udp.h>
#include <rrd.h>
#include "map.c"
#include "patriciatree.c"

#define ALARM_SLEEP 1
#define GRAPH_SLEEP 5
#define OPTIMIZE_SLEEP 6

#define DEFAULT_SNAPLEN 256
#define hash_DIM 256

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define NORMAL "\x1b[m"

uint32_t broadcastIP;
uint32_t allbroadcastIP;
uint32_t minMultiIP;
uint32_t maxMultiIP;
uint32_t intraIP;
uint32_t myIP;

typedef struct
{
    int src;
    int dst;
    long tx_packet;
    long rx_packet;
    long rx_packet_base;
    struct timeval time_src;
    struct timeval time_dst;
    //roaring_bitmap_t *bitmap;
    struct Node* root;
    int t_patricia; //number of node
} DATA;

pcap_t *pd;
int verbose = 0;
struct pcap_stat pcapStats;

roaring_bitmap_t *bitmap_BH;
hashmap *hash_BH;

struct timeval last_print;

/*************************************************/

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

    retStr = (char *)(cp + 1); // to lower case
    return (retStr);
}

/*************************************************/

//void optimize_entry(void *key, size_t ksize, uintptr_t d, void *usr)
//{
//    DATA *data = (DATA *)d;
//    roaring_bitmap_run_optimize(data->bitmap);
//}

/*************************************************/

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
char *intoa(unsigned int addr) { return (__intoa(addr, buf, sizeof(buf))); }

/*************************************************/

void sigproc(int sig)
{
    static int called = 0;
    fprintf(stderr, "Leaving...\n");
    if (called)
        return;
    else
        called = 1;
    pcap_breakloop(pd);
}

/*************************************************/

int min(time_t a, time_t b)
{
    if (a < b)
        return a;
    return b;
}

/*************************************************/
/*free the hashmap entry and the bitmap*/

void free_entry(struct timeval time_dst, struct timeval time_src, void *key, DATA *data)
{  
    struct timeval time;
    gettimeofday(&time, NULL);
    if (min(time.tv_sec - time_dst.tv_sec, time.tv_sec - time_src.tv_sec) > 300)
    {   
        uintptr_t r;
        //roaring_bitmap_free(data->bitmap);
        free(data);
        hashmap_remove(hash_BH, (in_addr_t *)key, sizeof(in_addr_t));
        free(key);
    }
}

/*************************************************/

void print_line_table(int c) {
    printf("|");
    switch (c)
    {
        case 0:
            printf("%s", RED);
            break;
        case 1:
            printf("%s", YELLOW);
            break;
        case 2:
            printf("%s", GREEN);
            break;
    }
    printf("⬤ ");
    printf("%s", NORMAL);
}

/*************************************************/
char* ips;

bool iter_port(uint32_t value, void* p)
{
    char s[500];
    sprintf(s, " %d ", value);
    strcat(ips,s); 
    return true;
}

bool it(uint32_t value, void* p)
{
    char rrdfile[200];
    char command[2200];
    uintptr_t r;
    ips = malloc(2000*sizeof(char));
    strcpy(ips,"");
    sprintf(rrdfile, "rrd_bin/db/%s", intoa(ntohl(value)));

    if (hashmap_get(hash_BH, &value, sizeof(value), &r)) 
    {
        DATA *data = (DATA *)r;            
        struct Result** r = traverseTree(data->root,data->t_patricia);
        for (int i=0; i<data->t_patricia; i++) {
            char s[500];
            sprintf(s, "ip %s porte ", intoa(ntohl(r[i]->ip)));
            strcat(ips,s); 
            roaring_iterate(r[i]->ports, iter_port, NULL);
        }
    }  

    sprintf(command, "rrdtool graph rrd_bin/graph/%s.png -w 1920 -h 1080 -D --start end-24h DEF:da1=%s.rrd:speed:AVERAGE LINE:da1#ff0000:'1' COMMENT:\"il blackhole è stato contattato da %s\"", intoa(ntohl(value)),rrdfile, ips);
    system(command);
    free(ips);
    return true; 
}

void rd_graph() {roaring_iterate(bitmap_BH, it, NULL);}

/*************************************************/

void rd_create(in_addr_t ip)
{
    char rrdfile[100];
    sprintf(rrdfile,"rrd_bin/db/%s.rrd",intoa(ntohl(ip)));
    int rra_step = 1;
    unsigned long start_time = 1621314000;
    unsigned long rrd_argc = 2;
    const char** rrd_argv = calloc(sizeof(char*),2);
    rrd_argv[0] = "DS:speed:GAUGE:10:0:1000000";
    rrd_argv[1] = "RRA:AVERAGE:0.5:1:86400";
    int ret = rrd_create_r(rrdfile, rra_step, start_time, rrd_argc, rrd_argv);
    if (ret != 0) {
        printf("Errore CREATE: %s \n", rrd_get_error());
        rrd_clear_error();
        return;
    }
    free(rrd_argv);
}

/*************************************************/

long rd_update(in_addr_t ip, long p,long base)
{
    char rrdfile[100];
    long res = p-base;
    sprintf(rrdfile,"rrd_bin/db/%s.rrd",intoa(ntohl(ip)));
    unsigned long rrd_argc = 1;
    char arg[100];
    const char** rrd_argv = calloc(sizeof(char*),1);
    sprintf(arg,"N:%ld",res);
    printf("faccio update: %s p:%lu base: %lu",arg, p, base);
    rrd_argv[0] = arg;
    int ret = rrd_update_r(rrdfile,NULL,rrd_argc, rrd_argv); 
    if (ret != 0) {
        printf("Errore UPDATE: %s \n", rrd_get_error());
        rrd_clear_error();
        return 0;
    }
    free(rrd_argv);
    return p;
}

/*************************************************/

void print_hash_entry(void *key, size_t ksize, uintptr_t d, void *usr)
{
    DATA *data = (DATA *)d;
    long delta = data->time_dst.tv_sec - data->time_src.tv_sec;
    if (!(data->src && !data->dst))
    {
        if ((delta==0 && data->tx_packet==0 && data->rx_packet>10)||delta > 20) //Black hole
        {
            print_line_table(0);
            if (roaring_bitmap_contains(bitmap_BH, *(in_addr_t *)key))
                data->rx_packet_base = rd_update(*(in_addr_t *)key, data->rx_packet, data->rx_packet_base);
            else
            {
                roaring_bitmap_add(bitmap_BH, *(in_addr_t *)key);
                data->rx_packet_base = data->rx_packet;
                rd_create(*(in_addr_t *)key);
            }
        }
        else if (delta > 10) //probably blackhole
        {
            print_line_table(1);
            if (roaring_bitmap_contains(bitmap_BH, *(in_addr_t *)key))
                data->rx_packet_base = rd_update(*(in_addr_t *)key, data->rx_packet, data->rx_packet_base);
            else
            {
                roaring_bitmap_add(bitmap_BH, *(in_addr_t *)key);
                data->rx_packet_base = data->rx_packet;
                rd_create(*(in_addr_t *)key);
            }
        }
        else if ((roaring_bitmap_contains(bitmap_BH, *(in_addr_t *)key) && delta < 5)) // Back to send Packets
        {
            print_line_table(2);
            roaring_bitmap_remove(bitmap_BH, *(in_addr_t *)key);
            char rrdfile[100];
            sprintf(rrdfile, "rrd_bin/db/%s", intoa(ntohl(*(in_addr_t *)key)));
            remove(rrdfile);
            sprintf(rrdfile, "rrd_bin/graph/%s", intoa(ntohl(*(in_addr_t *)key)));
            remove(rrdfile);
        }
        else {//normal Host 
            print_line_table(2); 
        }

        time_t d_time = data->time_dst.tv_sec;
        time_t s_time = data->time_src.tv_sec;
        struct tm *dst_time = localtime(&d_time);
        struct tm *src_time = localtime(&s_time);
        printf("| %-16s |", intoa(ntohl(*(__uint32_t *)key)));
        printf(" %2lld.%2lld.%-6lld |",(long long)dst_time->tm_hour, (long long)dst_time->tm_min, (long long)dst_time->tm_sec);
        printf(" %2lld.%2lld.%-6lld |",(long long)src_time->tm_hour, (long long)src_time->tm_min, (long long)src_time->tm_sec);
        printf(" %6ld:%-6ld |\n", data->rx_packet, data->tx_packet);
        
        struct Result** susu = traverseTree(data->root,data->t_patricia);
        printf("sender:\n");
        for (int i=0; i<data->t_patricia; i++) {
            printf("   ip: %s con le porte: ", intoa(ntohl(susu[i]->ip)));
            roaring_iterate(susu[i]->ports, iter, NULL);
            printf("\n");
        }
    }

    if (!(roaring_bitmap_contains(bitmap_BH, *(in_addr_t *)key)))
        free_entry(data->time_dst, data->time_src, key, data);
}
/*************************************************/

int c = 0;
int cont = 0;
void print_stats()
{
    printf("\n\n\n\nITER: %d\n", c++);
    printf("---------------------------------------------------------------------\n");
    printf("|  |        IP        | Last RX Time | Last TX Time | Packets RX:TX |  \n");
    hashmap_iterate(hash_BH, print_hash_entry, NULL);
    printf("---------------------------------------------------------------------\n");

    cont++;
    if ((cont % GRAPH_SLEEP) == 0) { rd_graph(); }
    if (cont >= OPTIMIZE_SLEEP)
    {
        //hashmap_iterate(hash_BH, optimize_entry, NULL);
        cont = 0;
    }
    //roaring_bitmap_run_optimize(bitmap_BH);
}

/*************************************************/

void free_hashmap(void *key, size_t ksize, uintptr_t d, void *usr)
{
    DATA *data = (DATA *)d;
    free(key);
    //TODO: free patricia tree
    
    //roaring_bitmap_free(data->bitmap);
    free(data);
}

/*************************************************/

void my_sigalarm(int sig)
{
    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

/*************************************************/

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

/*************************************************/

void getBroadCast(char *device)
{
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in *sa = NULL;
    struct sockaddr_in *su = NULL;
    struct sockaddr_in myip;
    struct sockaddr_in br;

    char subnet_mask[INET_ADDRSTRLEN];
    char ip[INET_ADDRSTRLEN];
    char broad[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strcmp(ifa->ifa_name, device) == 0 && ifa->ifa_addr->sa_family == AF_INET)
        {
            sa = (struct sockaddr_in *)ifa->ifa_netmask;
            su = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), subnet_mask, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(su->sin_addr), ip, INET_ADDRSTRLEN);
            break;
        }
    }
    inet_pton(AF_INET, ip, &myip.sin_addr);
    myIP = ntohl(myip.sin_addr.s_addr);
    br.sin_addr.s_addr = su->sin_addr.s_addr | ~(sa->sin_addr.s_addr);
    broadcastIP = ntohl(br.sin_addr.s_addr);
    inet_ntop(AF_INET, &(br.sin_addr), broad, INET_ADDRSTRLEN);
    printf("\nSubnetMask:%s \nLocalIP:%s \nBroadcastIP: %s\n", subnet_mask, ip, broad);
    freeifaddrs(ifaddr);
}

/*************************************************/

void dummyProcesssPacket(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p)
{
    struct ether_header ehdr;
    struct ip ip;
    struct tcphdr tcp_hdr;

    if (h->caplen < (sizeof(struct ether_header) + sizeof(struct ip)))
        return;

    memcpy(&ehdr, p, sizeof(struct ether_header));
    u_short eth_type = ntohs(ehdr.ether_type);

    if (eth_type == 0x0800)
    {
        memcpy(&ip, p + sizeof(ehdr), sizeof(struct ip));
        uint32_t dst_ip = ntohl(ip.ip_dst.s_addr);

        if (ip.ip_p == IPPROTO_TCP &&
                (dst_ip != broadcastIP) &&
                (dst_ip != intraIP) &&
                //(ntohl(ip.ip_dst.s_addr) != ntohl(myIP.sin_addr.s_addr)) &&
                //(ntohl(ip.ip_src.s_addr) != ntohl(myIP.sin_addr.s_addr)) &&
                (dst_ip != allbroadcastIP) &&
                (dst_ip < minMultiIP || dst_ip > maxMultiIP))
        {   

            memcpy(&tcp_hdr, p + sizeof(ehdr) + sizeof(ip), sizeof(struct tcphdr));
            //printf("src_p %hu   dst_p %hu\n",tcp_hdr.th_dport, tcp_hdr.th_sport);
            //time_dst = last rx packet time, time_src = last tx packet time, if host have only rx traffics, time_src = last rx packet time 
            uintptr_t r;
            if (hashmap_get(hash_BH, &ip.ip_src.s_addr, sizeof(ip.ip_src.s_addr), &r)) // src ip present in the hashmap 
            {
                DATA *data = (DATA *)r;
                data->tx_packet++;
                if (!(data->src)) //host was only dst
                    data->src = 1;
                data->time_src = h->ts; //update last rx time packet
            }
            else // src ip not present in the hashmap
            {
                DATA *src_data;
                src_data = malloc(sizeof(DATA));
                src_data->src = 1;
                src_data->dst = 0;
                src_data->rx_packet = 0;
                src_data->tx_packet = 1;
                src_data->time_src = h->ts;
                src_data->t_patricia = 0;
                src_data->root = createNode();

                in_addr_t *s_addr = malloc(sizeof(in_addr_t));
                memcpy(s_addr, &ip.ip_src.s_addr, sizeof(in_addr_t));
                hashmap_set(hash_BH, s_addr, sizeof(in_addr_t), (uintptr_t)(void *)src_data);
            }

            if (hashmap_get(hash_BH, &ip.ip_dst.s_addr, sizeof(ip.ip_dst.s_addr), &r)) // DST not present in the hashmap
            {
                DATA *data = (DATA *)r;
                data->rx_packet++;
                if (!(data->dst)) // was only src
                    data->dst = 1; 
                data->time_dst = h->ts;
                
                roaring_bitmap_t* bitmap = search(data->root,(uint32_t)ip.ip_src.s_addr);
                if (bitmap != NULL) {
                    roaring_bitmap_add(bitmap, tcp_hdr.th_dport);
                } else {
                    data->t_patricia = insert(data->root, (uint32_t)ip.ip_src.s_addr, data->t_patricia);
                    roaring_bitmap_t* bitmap_c = search(data->root,(uint32_t)ip.ip_src.s_addr);
                    roaring_bitmap_add(bitmap_c, tcp_hdr.th_dport);
                }
            }
            else // DST not present
            {
                DATA *dst_data = malloc(sizeof(DATA));
                dst_data->dst = 1;
                dst_data->src = 0;
                dst_data->rx_packet = 1;
                dst_data->tx_packet = 0;
                dst_data->time_src = h->ts;
                dst_data->time_dst = h->ts;
                dst_data->t_patricia = 0;
                dst_data->root = createNode();

                dst_data->t_patricia = insert(dst_data->root, (uint32_t)ip.ip_src.s_addr, dst_data->t_patricia);
                roaring_bitmap_t* b = search(dst_data->root,(uint32_t)ip.ip_src.s_addr);
                roaring_bitmap_add(b, tcp_hdr.th_dport);

                in_addr_t *s_addr = malloc(sizeof(in_addr_t));
                memcpy(s_addr, &ip.ip_dst.s_addr, sizeof(in_addr_t));
                hashmap_set(hash_BH, s_addr, sizeof(in_addr_t), (uintptr_t)(void *)dst_data);
            }
        }
        struct timeval now;
        gettimeofday(&now, NULL);
        if ((now.tv_sec - last_print.tv_sec) > 1){
            print_stats();
            gettimeofday(&last_print, NULL);
        }
    }
}

/*************************************************/

int main(int argc, char *argv[])
{
    char *device = NULL;
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc, snaplen = DEFAULT_SNAPLEN;
    bitmap_BH = roaring_bitmap_create();
    hash_BH = hashmap_create();

    system("mkdir rrd_bin");
    system("mkdir rrd_bin/db");
    system("mkdir rrd_bin/graph");

    while ((c = getopt(argc, argv, "hi:l:v:f:")) != '?')
    {
        if ((c == 255) || (c == (u_char)-1))
            break;
        switch (c)
        {
            case 'i':
                device = strdup(optarg);
                break;
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
        return (-1);
    }

    printf("Capturing from %s\n", device);
    getBroadCast(device);

    struct sockaddr_in allbroadcastip;
    struct sockaddr_in minMultiip;
    struct sockaddr_in maxMultiip;
    struct sockaddr_in intraip;

    inet_pton(AF_INET, "224.0.0.0", &minMultiip.sin_addr);
    inet_pton(AF_INET, "239.255.255.255", &maxMultiip.sin_addr);
    inet_pton(AF_INET, "255.255.255.255", &allbroadcastip.sin_addr);
    inet_pton(AF_INET, "192.168.222.11", &intraip.sin_addr);

    allbroadcastIP = ntohl(allbroadcastip.sin_addr.s_addr);
    minMultiIP = ntohl(minMultiip.sin_addr.s_addr);
    maxMultiIP = ntohl(maxMultiip.sin_addr.s_addr);
    intraIP = ntohl(intraip.sin_addr.s_addr);

    promisc = 1;
    if ((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL)
    {
        printf("pcap_open_live: %s\n", errbuf);
        return (-1);
    }

    gettimeofday(&last_print, NULL);

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    pcap_loop(pd, -1, dummyProcesssPacket, NULL);
    pcap_close(pd);

    roaring_bitmap_free(bitmap_BH);
    hashmap_iterate(hash_BH, free_hashmap, NULL);
    hashmap_free(hash_BH);
    return (0);
}