#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>
#include <pwd.h>
#include "uthash.h"
#include <signal.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ndpi/ndpi_api.h>

#define INTERVAL 1
char MIO_IP[INET_ADDRSTRLEN];

typedef struct {
    char protocol[32];
    unsigned long bytes;
    int local;
    int ruolo;
    UT_hash_handle hh;
} ip_stat;

struct ndpi_detection_module_struct *ndpi_struct = NULL;

typedef struct {
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;
    uint8_t  l4_proto;

    struct ndpi_flow_struct *ndpi_flow;

    ndpi_protocol detected_proto;
    uint8_t       detection_done;

    UT_hash_handle hh;
} flow_entry;

flow_entry *flow_table = NULL;

ip_stat *table = NULL;
pcap_t  *handle = NULL;
unsigned long byte_global = 0;
struct timeval start_time;
unsigned long byte_local  = 0;
long current_time = 0;

void get_local_ip(const char *interface);
void free_table();
void free_flow_table();
void init_ndpi();
int  drop_privileges(const char *username);
void sigproc(int sig);
void update_ip(const char *ip_dst, unsigned long bytes,
               const char *ip_srg, const char *app_protocol);
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);
void print_table(double dt);
void print_stats(double throughput_global, double dt);
void run_offline(const char *filename);

void get_local_ip(const char *interface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("Errore apertura socket per IP"); return; }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
        inet_ntop(AF_INET, &ipaddr->sin_addr, MIO_IP, INET_ADDRSTRLEN);
        printf("Indirizzo IP di %s trovato: %s\n", interface, MIO_IP);
    } else {
        perror("Errore ioctl");
        strcpy(MIO_IP, "0.0.0.0");
    }
    close(fd);
}

void free_table() {
    ip_stat *current, *tmp;
    HASH_ITER(hh, table, current, tmp) {
        HASH_DEL(table, current);
        free(current);
    }
}

void free_flow_table() {
    flow_entry *fe, *tmp;
    HASH_ITER(hh, flow_table, fe, tmp) {
        HASH_DEL(flow_table, fe);
        if (fe->ndpi_flow) ndpi_free_flow(fe->ndpi_flow);
        free(fe);
    }
}


void init_ndpi() {
    ndpi_struct = ndpi_init_detection_module(NULL);
    if (!ndpi_struct) {
        fprintf(stderr, "Errore: ndpi_init_detection_module fallita\n");
        exit(1);
    }

    if (ndpi_finalize_initialization(ndpi_struct) != 0) {
        fprintf(stderr, "Errore: ndpi_finalize_initialization fallita\n");
        exit(1);
    }

    printf("nDPI %s inizializzato\n", ndpi_revision());
}

int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw != NULL) {
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) return -1;
        fprintf(stderr, "Sicurezza: utente cambiato in %s\n", username);
    }
    return 0;
}

void sigproc(int sig) {
    fprintf(stderr, "Chiusura in corso...\n");
    if (handle) pcap_breakloop(handle);
    free_flow_table();
    if (ndpi_struct) ndpi_exit_detection_module(ndpi_struct);
    free_table();
    printf("----------FINE CATTURA----------\n");
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    printf("durata cattura[t = %ld]\n", end_time.tv_sec - start_time.tv_sec);
    exit(0);
}

void run_offline(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(filename, errbuf);
    if (!handle) { fprintf(stderr, "Errore apertura file: %s\n", errbuf); exit(1); }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    struct pcap_pkthdr *header;
    const u_char *packet;

    struct timeval file_start   = {0, 0};
    struct timeval window_start = {0, 0};
    struct timeval prev_ts      = {0, 0};
    int first = 1;

    gettimeofday(&start_time, NULL);

    while (pcap_next_ex(handle, &header, &packet) == 1) {

        if (first) {
            file_start   = header->ts;
            window_start = header->ts;
        }

        if (!first) {
            long delta_us = (header->ts.tv_sec  - prev_ts.tv_sec)  * 1000000 +
                            (header->ts.tv_usec - prev_ts.tv_usec);
            if (delta_us > 0) {
                if (delta_us > 1000000) delta_us = 1000000;
                usleep(delta_us);
            }
        }
        prev_ts = header->ts;

        long elapsed = (header->ts.tv_sec  - window_start.tv_sec) * 1000000 +
                       (header->ts.tv_usec - window_start.tv_usec);

        if (!first && elapsed >= INTERVAL * 1000000) {
            double dt = elapsed / 1e6;
            current_time = window_start.tv_sec - file_start.tv_sec;
            print_stats(byte_local / dt, dt);
            window_start = header->ts;
        }

        first = 0;

        packet_handler(NULL, header, packet);
    }

    if (byte_global > 0) {
        current_time = window_start.tv_sec - file_start.tv_sec;
        print_stats(byte_local / 1.0, 1.0);
    }

    pcap_close(handle);
}

void update_ip(const char *ip_srg, unsigned long bytes,
               const char *ip_dst, const char *app_protocol) {
    ip_stat *s = NULL;

    HASH_FIND_STR(table, app_protocol, s);
    if (s == NULL) {
        s = malloc(sizeof(ip_stat));
        memset(s, 0, sizeof(ip_stat));
        strncpy(s->protocol, app_protocol, sizeof(s->protocol) - 1);


            if (strcmp(ip_dst, MIO_IP) == 0 || strcmp(ip_srg, MIO_IP) == 0) {
                s->local = 1;
                s->ruolo = (strcmp(ip_dst, MIO_IP) == 0) ? 0 : 1;
                } else {
                    s->local = 0;
                    s->ruolo = -1;
                }
        HASH_ADD_STR(table, protocol, s);
    }

    s->bytes += bytes;
    byte_global += bytes;
    if (s->local) byte_local += bytes;


}

void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet) {

    if (header->caplen < 14 + sizeof(struct ip)) return;

    struct ip *ip_hdr = (struct ip *)(packet + 14);

    if (ip_hdr->ip_v != 4) return;

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_str, INET_ADDRSTRLEN);

    uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr);
    uint32_t dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
    uint8_t  l4_proto = ip_hdr->ip_p;

    uint16_t src_port = 0, dst_port = 0;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char *l4 = (const u_char *)ip_hdr + ip_hdr_len;

    int l4_avail = header->caplen - 14 - ip_hdr_len;

    if (l4_proto == IPPROTO_TCP && l4_avail >= (int)sizeof(struct tcphdr)) {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (l4_proto == IPPROTO_UDP && l4_avail >= (int)sizeof(struct udphdr)) {
        struct udphdr *udp = (struct udphdr *)l4;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;
    if (src_ip <= dst_ip) {
        ip_a = src_ip; ip_b = dst_ip;
        port_a = src_port; port_b = dst_port;
    } else {
        ip_a = dst_ip; ip_b = src_ip;
        port_a = dst_port; port_b = src_port;
    }

    typedef struct {
            uint32_t ia, ib;
            uint16_t pa, pb;
            uint8_t proto;
    } FlowKey;
    FlowKey key;
    memset(&key, 0, sizeof(FlowKey));
    key.ia = ip_a; key.ib = ip_b;
    key.pa = port_a; key.pb = port_b;
    key.proto = l4_proto;

    flow_entry *fe = NULL;
    HASH_FIND(hh, flow_table, &key, sizeof(FlowKey), fe);

    if (fe == NULL) {
        fe = calloc(1, sizeof(flow_entry));
        fe->ip_a = ip_a; fe->ip_b = ip_b;
        fe->port_a = port_a; fe->port_b = port_b;
        fe->l4_proto = l4_proto;

        fe->ndpi_flow = calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());

        fe->detection_done = 0;
        fe->detected_proto.proto.master_protocol = NDPI_PROTOCOL_UNKNOWN;
        fe->detected_proto.proto.app_protocol    = NDPI_PROTOCOL_UNKNOWN;

        HASH_ADD(hh, flow_table, ip_a, sizeof(FlowKey), fe);
    }

    if (!fe->detection_done) {
        uint64_t time_ms = (uint64_t)header->ts.tv_sec * 1000 +
                           header->ts.tv_usec / 1000;

        const uint8_t *l3 = (const uint8_t *)ip_hdr;
        uint16_t avail   = header->caplen - 14;
        uint16_t l3_len  = ntohs(ip_hdr->ip_len);
        if (l3_len == 0 || l3_len > avail)
            l3_len = avail;

        fe->detected_proto = ndpi_detection_process_packet(
            ndpi_struct,
            fe->ndpi_flow,
            l3, l3_len,
            time_ms,
            NULL
        );
        int soglia = (fe->l4_proto == IPPROTO_TCP) ? 80 : 24;
        if (fe->ndpi_flow->num_processed_pkts >= soglia &&
            fe->detected_proto.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
            fe->detected_proto.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {

            u_int8_t proto_guessed = 0;
            fe->detected_proto = ndpi_detection_giveup(
                ndpi_struct, fe->ndpi_flow
            );
            fe->detection_done = 1;
        }

        if (fe->detected_proto.proto.app_protocol    != NDPI_PROTOCOL_UNKNOWN ||
            fe->detected_proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            fe->detection_done = 1;
        }
    }

    uint16_t proto_id;
    if (fe->detected_proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        proto_id = fe->detected_proto.proto.app_protocol;
    else if (fe->detected_proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        proto_id = fe->detected_proto.proto.master_protocol;
    else
        proto_id = NDPI_PROTOCOL_UNKNOWN;

    const char *proto_name = ndpi_get_proto_name(ndpi_struct, proto_id);
    if (!proto_name || strlen(proto_name) == 0)
        proto_name = "Unknown";

    update_ip(src_str, header->len, dst_str, proto_name);
}

void print_table(double dt) {
    ip_stat *s;
    for (s = table; s != NULL; s = s->hh.next) {
        printf("  %-20s  %8.2ld Byte", s->protocol, s->bytes);
        if (s->local)
            printf("  [%s]", s->ruolo == 0 ? "IN" : "OUT");
        else
            printf("  [TRANSIT]");
        printf("\n");
    }
}

void print_stats(double throughput_local, double dt) {
    double rate_global = byte_global / dt;

    printf("\n[t = %ld]-----------------------------\n", current_time);
    printf("Throughput globale:  %.2f B/s\n", rate_global);
    printf("Throughput locale:   %.2f B/s\n", throughput_local);
    printf("Protocolli osservati:\n");
    print_table(dt);

    free_table();
    byte_global = 0;
    byte_local  = 0;
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "Uso: %s <interfaccia> <live|offline>\n", argv[0]);
        return 1;
    }

    char *interface = argv[1];
    char *modalita  = argv[2];

    signal(SIGINT, sigproc);

    char errbuf[PCAP_ERRBUF_SIZE];
    gettimeofday(&start_time, NULL);

    init_ndpi();

    if (strcmp(modalita, "offline") == 0){
        if (argc >= 4) {
            strncpy(MIO_IP, argv[3], INET_ADDRSTRLEN - 1);
            MIO_IP[INET_ADDRSTRLEN - 1] = '\0';
        } else {
            strcpy(MIO_IP, "0.0.0.0");
        }
        run_offline(interface);
        free_flow_table();
        ndpi_exit_detection_module(ndpi_struct);
        return 0;
    }

    get_local_ip(interface);

    handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
    if (!handle) { fprintf(stderr, "Errore pcap: %s\n", errbuf); return 1; }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);
    drop_privileges("nobody");

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    while (true) {
        struct timeval now;
        do {
            pcap_dispatch(handle, -1, packet_handler, NULL);
            gettimeofday(&now, NULL);
        } while (((now.tv_sec  - t1.tv_sec)  * 1000000 +
                  (now.tv_usec - t1.tv_usec)) < (INTERVAL * 1000000));

        gettimeofday(&t2, NULL);
        double dt = (t2.tv_sec  - t1.tv_sec) +
                    (t2.tv_usec - t1.tv_usec) / 1e6;
        current_time = t2.tv_sec - start_time.tv_sec;
        print_stats(byte_local / dt, dt);
        t1 = t2;
    }

    pcap_close(handle);
    free_flow_table();
    ndpi_exit_detection_module(ndpi_struct);
    return 0;
}