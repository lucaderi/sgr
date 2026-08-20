/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 *
 * gcc latency.c -o latency -lpcap
 *
*/


#define _GNU_SOURCE

#include <pcap/pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <stdbool.h>
#include <math.h>


#define DEFAULT_SNAPLEN 256
#define HASHTABLE_SIZE 65536
pcap_t  *pd;



/* Visual Studio */
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;


/* Data structure for hash table's keys */
typedef struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key;


/* Data structure for hash table's entries */
typedef struct flow_entry {
    flow_key key;
    struct timeval syn_time;
    struct flow_entry *next;
} flow_entry;



static flow_entry *hash_table[HASHTABLE_SIZE];
unsigned long long numPkts = 0, numBytes = 0;
unsigned long long syn_count = 0, synack_count = 0, completed_rounds = 0;
double min_latency = INFINITY, max_latency = 0, sum_latencies = 0, latencies_computed = 0;
pcap_dumper_t *dumper = NULL;



/* Prototypes*/
flow_key build_key(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dstport, uint8_t protocol);
unsigned int hash_flow_key(flow_key *k);
bool key_equals(flow_key *a, flow_key *b);
flow_key reverse_key(flow_key key);
flow_entry *table_lookup(flow_key *key);
flow_entry *table_insert(flow_key *key, const struct timeval *syn_time);
void table_delete(flow_key *key);
void free_table();
double compute_diff_ms(struct timeval *a, struct timeval *b);
int drop_privileges(const char *username);
void print_stats();
void printHelp();
void update_latency_stats(double l);
void sigproc(int sig);
void processPacket (u_char *deviceId, const struct pcap_pkthdr *h, const u_char *p);



/* *************************************** */

flow_key build_key(uint32_t src_ip, 
                   uint32_t dst_ip, 
                   uint16_t src_port, 
                   uint16_t dstport,
                   uint8_t protocol
                  ) {

   flow_key key;
   key.src_ip = src_ip;
   key.dst_ip = dst_ip;
   key.src_port = src_port;
   key.dst_port = dstport;
   key.protocol = protocol;

   return key;
}


/* *************************************** */

unsigned int hash_flow_key(flow_key *k) {
    
    if (k == NULL) return 0;
    unsigned int p = 31;

    return ((k->src_ip * p * p * p * p) +
           (k->dst_ip * p * p * p) +
           (k->src_port * p * p) +
           (k->dst_port * p) +
           k->protocol) %
           HASHTABLE_SIZE;
}


/* *************************************** */

bool key_equals(flow_key *a, flow_key *b) {
    
    if (a == NULL || b == NULL) return false;

    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}


/* *************************************** */

flow_key reverse_key(flow_key key) {
    
    flow_key rkey;
    rkey.src_ip = key.dst_ip;
    rkey.dst_ip = key.src_ip;
    rkey.src_port = key.dst_port;
    rkey.dst_port = key.src_port;
    rkey.protocol = key.protocol;
    return rkey;
}


/* *************************************** */

flow_entry *table_lookup(flow_key *key) {

    if (key == NULL) return NULL;
    unsigned int index = hash_flow_key(key);
    flow_entry *curr = hash_table[index];
    while (curr != NULL) {
        if (key_equals(&curr->key, key)) return curr;
        curr = curr->next;
    }
    return NULL;
    }


/* *************************************** */

flow_entry *table_insert(flow_key *key, const struct timeval *syn_time) {

    if (key == NULL || syn_time == NULL) return NULL;
    unsigned int index = hash_flow_key(key);
    flow_entry *entry = calloc(1, sizeof(flow_entry));
    if (entry == NULL) return NULL;

    entry->key = *key;
    entry->syn_time = *syn_time;
    entry->next = hash_table[index];
    hash_table[index] = entry;

    return entry;
    }


/* *************************************** */

void table_delete(flow_key *key) {
    
    if (key == NULL) return;
    unsigned int index = hash_flow_key(key);
    flow_entry *curr = hash_table[index];
    flow_entry *prev = NULL;

    while (curr != NULL) {
        if (key_equals(&curr->key, key)) {
            if (prev == NULL) hash_table[index] = curr->next;
            else prev->next = curr->next;

            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}


/* *************************************** */

void free_table() {
    for (int i = 0; i < HASHTABLE_SIZE; i++) {
        flow_entry *curr = hash_table[i];
        while (curr != NULL) {
            flow_entry *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
        hash_table[i] = NULL;
    }
}


/* *************************************** */

double compute_diff_ms(struct timeval *a, struct timeval *b) {

    if (a == NULL || b == NULL) return -1;
    double sec = (double)(a->tv_sec - b->tv_sec) * 1000.0;
    double usec = (double)(a->tv_usec - b->tv_usec) / 1000.0;
    return sec + usec;
}


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

    printf("=========================\n");
    printf("Total TCP Pkts=%llu | Total Bytes=%llu.\n", numPkts, numBytes);
    printf("=========================\n");
    printf("Total SYNs=%llu | ", syn_count);
    printf("Total SYNACKSs=%llu | ", synack_count);
    printf("Completed Rounds=%llu.\n", completed_rounds);
    printf("=========================\n");
    if (latencies_computed > 0) {
        printf("Min latency=%fms | ", min_latency);
        printf("Max latency=%fms | ", max_latency);
        printf("Avg latency=%fms.\n", sum_latencies / latencies_computed);
    } else {
        printf("No latencies computed.\n");
    }
    printf("=========================\n");
}


/* *************************************** */

void printHelp() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("Usage: latency [-h] -i <device|path>\n");
    printf("-h                Print help\n");
    printf("-i <device|path>  Device name or file path\n");

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

void update_latency_stats(double l) {

    if (l < min_latency) min_latency = l;
    if (l >= max_latency) max_latency = l;
    sum_latencies += l;
    latencies_computed++;
}


/* *************************************** */

void sigproc(int sig) {

    static int called = 0;
    fprintf(stderr, "Leaving...\n");
    if (called) return; else called = 1;
    pcap_breakloop(pd);
}


/* *************************************** */

void processPacket (u_char *deviceId,
                    const struct pcap_pkthdr *h,
                    const u_char *p) {

    struct ether_header ehdr;
	u_short eth_type;
	struct iphdr ip;
    struct tcphdr tcp;
    flow_key key, rkey;
    flow_entry *entry;
    char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
    double latency;
    int ip_hdr_len;

    if (dumper) pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)h, p);
    
    /* Pkts header length controls */
    if (h->caplen < sizeof(struct ether_header)) return;

    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);

    if (eth_type != 0x800) return;
    if (h->caplen < sizeof(struct ether_header) + sizeof(struct iphdr)) return;

    memcpy(&ip, p + sizeof(struct ether_header), sizeof(struct iphdr));

    ip_hdr_len = ip.ihl * 4;

    if (ip_hdr_len < sizeof(struct iphdr)) return;
    if (h->caplen < sizeof(struct ether_header) + ip_hdr_len) return;

    if (ip.protocol != IPPROTO_TCP) return;
    if (h->caplen < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr)) return;

    memcpy(&tcp, p + sizeof(struct ether_header) + ip_hdr_len, sizeof(struct tcphdr));
    
    key = build_key(ip.saddr, ip.daddr, tcp.source, tcp.dest, ip.protocol);
    
    /* Increasing global pkts and bytes counters */
    numPkts++;
    numBytes += h->caplen;

    if ((tcp.th_flags & TH_SYN) && !(tcp.th_flags & TH_ACK)) {
        /* SYN */
        syn_count++;
        entry = table_lookup(&key);
        if (entry == NULL) entry = table_insert(&key, &h->ts);
        /* Retransmissions and their timestamp are ignored */
    }

    if ((tcp.th_flags & TH_SYN) && (tcp.th_flags & TH_ACK)) {
        /* SYN-ACK */
        synack_count++;
        rkey = reverse_key(key);
        entry = table_lookup(&rkey);

        if (entry != NULL) {
            latency = compute_diff_ms((struct timeval *)&h->ts, &entry->syn_time);
            completed_rounds++;
            update_latency_stats(latency);
            printf("[%s", inet_ntop(AF_INET, &(ip.daddr), ip1, INET_ADDRSTRLEN));
            printf(" -> %s] latency: %f ms\n", inet_ntop(AF_INET, &(ip.saddr), ip2, INET_ADDRSTRLEN), latency);
            table_delete(&rkey);
        } 
    }  
}


/* *************************************** */

int main(int argc, char* argv[]) {
    char *device = NULL, *bpfFilter = NULL;
    u_char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen = DEFAULT_SNAPLEN;
    struct stat s;
    struct bpf_program fcode;

    while((c = getopt(argc, argv, "hi:w:")) != '?') {
        if ((c == 255) || (c == (u_char)-1)) break;

        switch(c) {
        case 'h':
            printHelp();
            exit(0);
            break;

        case 'i':
            device = strdup(optarg);
            break;
        
        case 'w':
            dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384), optarg);
            if (dumper == NULL) {
                printf("Unable to open dump file %s\n", optarg);
                return(-1);
            }
        }
    }

    if (device == NULL) {
        printf("ERROR: Missing -i\n");
        printHelp();
        return(-1);
    }

    printf("Capturing from %s\n", device);

    if (stat(device, &s) == 0) {
	    /* Device is a file on filesystem */
        if ((pd = pcap_open_offline(device, errbuf)) == NULL) {
	        printf("pcap_open_offline: %s\n", errbuf);
	        return(-1);
	    }
    } else {
        if (geteuid() != 0) {
            printf("Please run this tool as superuser when capturing from a live interface\n");
            return(-1);
        }
        if ((pd = pcap_open_live(device, snaplen, 1, 500, errbuf)) == NULL) {
            printf("pcap_open_live: %s\n", errbuf);
            return(-1);
        }
    }
    
    /* Hardcoded BPF filter for TCP packets */
    bpfFilter = "tcp";
    if (pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    else {
        if(pcap_setfilter(pd, &fcode) < 0) printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
    }
    
    if (geteuid() == 0) {
        if (drop_privileges("nobody") < 0) return(-1);
    }

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    pcap_loop(pd, -1, processPacket, NULL);
    
    print_stats();

    free_table();
    pcap_close(pd);
    if (dumper) pcap_dump_close(dumper);

    return(0);
}