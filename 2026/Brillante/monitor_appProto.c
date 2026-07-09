#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "ndpi_api.h"
#include <getopt.h>


#define INTERVAL 1
char MIO_IP[INET_ADDRSTRLEN];

typedef struct {
    char protocol[32];
    unsigned long bytes;
    unsigned long pkts;
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
ip_stat *total_table = NULL;               
unsigned long total_pkts_global = 0;
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
void print_table();
void print_stats(double throughput_global, double dt);
void run_offline(const char *filename);
void print_final_stats();
void free_total_table();

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

void print_final_stats() {
    printf("\n========== RIEPILOGO CATTURA ==========\n");
    printf("Pacchetti totali analizzati: %lu\n", total_pkts_global);
    printf("Totali per protocollo:\n");
    ip_stat *s;
    for (s = total_table; s != NULL; s = s->hh.next)
        printf("  %-20s %8lu pkt  %12lu Byte\n", s->protocol, s->pkts, s->bytes);
}

void free_total_table() {
    ip_stat *current, *tmp;
    HASH_ITER(hh, total_table, current, tmp) {
        HASH_DEL(total_table, current);
        free(current);
    }
}

void sigproc(int sig) {
    fprintf(stderr, "Chiusura in corso...\n");
    if (handle) pcap_breakloop(handle);
    print_final_stats(); 
    free_flow_table();
    free_total_table();
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
    print_final_stats();
    free_total_table();
    pcap_close(handle);
}

void update_ip(const char *ip_srg, unsigned long bytes,
               const char *ip_dst, const char *app_protocol) {
    ip_stat *s = NULL;

    HASH_FIND_STR(table, app_protocol, s);
    if (s == NULL) {
        s = calloc(1, sizeof(ip_stat));
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
    s->pkts  += 1;
    byte_global += bytes;
    if (s->local) byte_local += bytes;


    ip_stat *t = NULL;
    HASH_FIND_STR(total_table, app_protocol, t);
    if (t == NULL) {
        t = calloc(1, sizeof(ip_stat));
        strncpy(t->protocol, app_protocol, sizeof(t->protocol) - 1);
        HASH_ADD_STR(total_table, protocol, t);
    }
    t->bytes += bytes;
    t->pkts  += 1;
    total_pkts_global++;
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

    if (l4_proto == IPPROTO_TCP && l4_avail >= (int)sizeof(struct ndpi_tcphdr)) {
        struct ndpi_tcphdr *tcp = (struct ndpi_tcphdr *)l4;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (l4_proto == IPPROTO_UDP && l4_avail >= (int)sizeof(struct ndpi_udphdr)) {
        struct ndpi_udphdr *udp = (struct ndpi_udphdr *)l4;
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

        ndpi_protocol detected = ndpi_detection_process_packet(
            ndpi_struct,
            fe->ndpi_flow,
            l3, l3_len,
            time_ms,
            NULL
        );
        
        if (detected.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
            detected.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            
            fe->detected_proto = detected;
            fe->detection_done = 1;
            
        } else {
            int soglia = (fe->l4_proto == IPPROTO_TCP) ? 80 : 24;
            
            if (fe->ndpi_flow->num_processed_pkts >= soglia) {
                fe->detected_proto = ndpi_detection_giveup(ndpi_struct, fe->ndpi_flow);
                fe->detection_done = 1;
            }
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

void print_table() {
    ip_stat *s;
    for (s = table; s != NULL; s = s->hh.next) {
        printf("  %-20s %10lu Byte %6lu pkt", s->protocol, s->bytes, s->pkts);
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
    print_table();

    free_table();
    byte_global = 0;
    byte_local  = 0;
}

void info_argomenti_linea_comando(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s -i <interfaccia>           cattura live (richiede root)\n"
        "  %s -f <file.pcap> [-a <ip>]   analisi offline\n"
        "Opzioni:\n"
        "  -i <iface>  interfaccia di rete (es. eth0)\n"
        "  -f <file>   file pcap da analizzare\n"
        "  -a <ip>     proprio IP, per marcare IN/OUT in offline\n"
        "  -h          aiuto\n",
        prog, prog);
}

int main(int argc, char *argv[]) {

    char *interface = NULL, *pcap_file = NULL, *local_ip = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:a:h")) != -1) {
        switch (opt) {
        case 'i': interface = optarg; break;
        case 'f': pcap_file = optarg; break;
        case 'a': local_ip  = optarg; break;
        case 'h': info_argomenti_linea_comando(argv[0]); return 0;
        default:  info_argomenti_linea_comando(argv[0]); return 1;
        }
    }

    
    if ((interface && pcap_file) || (!interface && !pcap_file)) {//per verificare che l'utente inserisca -i o -f
        fprintf(stderr, "Errore: specificare -i (live) oppure -f (offline)\n");
        info_argomenti_linea_comando(argv[0]);
        return 1;
    }

    if (local_ip) {
        struct in_addr tmp;
        if (inet_pton(AF_INET, local_ip, &tmp) != 1) {
            fprintf(stderr, "Errore: IP non valido '%s'\n", local_ip);
            return 1;
        }
    }

    // MODALITà OFFLINE
    signal(SIGINT, sigproc);
    gettimeofday(&start_time, NULL);
    init_ndpi();

    if (pcap_file) {                       
        if (local_ip) {
            strncpy(MIO_IP, local_ip, INET_ADDRSTRLEN - 1);
            MIO_IP[INET_ADDRSTRLEN - 1] = '\0';
        } else {
            strcpy(MIO_IP, "0.0.0.0");
        }
        run_offline(pcap_file);
        free_flow_table();
        ndpi_exit_detection_module(ndpi_struct);
        return 0;
    }


    //Modalità Live
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