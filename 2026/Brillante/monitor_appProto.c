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
 
 
#define INTERVAL 1 //intervallo della finestra di output e di analisi

//stessa logica di nDPI-reader e sono costanti che servono per indicare quando eliminare i flussi inattivi

#define MAX_IDLE_TIME     300000   /* ms, come ndpiReader --> indica dopo quanto un flusso viene considerato inattivo*/ 
#define IDLE_SCAN_PERIOD  10       /* ms tra una scansione e la successiva --> tempo per la scansione della tabella e vedere quali flussi sono inattivi*/
#define IDLE_SCAN_BUDGET  1024     /* max flussi eliminati */
char MIO_IP[INET_ADDRSTRLEN]; // la costante tra le [] è la lunghezza massima di un indirizzo ipV4
 
typedef struct {
    char protocol[32]; //nome del protocollo
    unsigned long bytes;
    unsigned long pkts;
    int local; //se è traffito locale
    int ruolo; //in base al valore indica se IN OUT o transito
    UT_hash_handle hh; //aggancio che rende la struct inseribile in una struttura hash
} ip_stat;
 
/* Chiave canonica del flusso (IP e porte ordinati + protocollo L4).
 * Definita a livello globale e incorporata in flow_entry, cosi' la
 * chiave usata da uthash e' esattamente questa struttura e non dipende
 * dall'ordine dei campi di flow_entry. */
typedef struct {
    uint32_t ia, ib; //i due ip del flusso
    uint16_t pa, pb; //le due porte nello stesso ordine degli IP
    uint8_t  proto; //numero protocollo
} FlowKey;
 
struct ndpi_detection_module_struct *ndpi_struct = NULL;
 
typedef struct {
    FlowKey key;                       /* chiave della tabella hash */
 
    struct ndpi_flow_struct *ndpi_flow; //lo stato che nDPI accumula per queso flusso
 
    ndpi_protocol detected_proto; // il protocollo rilevato che può essere unknown
    uint8_t       detection_done; // quando la classificazioneè conclusa
    uint64_t      last_seen_ms;        /* timestamp dell'ultimo pacchetto visto */
 
    UT_hash_handle hh; //aggancio utash
} flow_entry;
 
flow_entry *flow_table = NULL; //puntatore al primo elemento che identifica la tabella hash dei flussi
 
/* Stato della scansione dei flussi idle (equivalente dei campi
 * last_idle_scan_time / idle_flows / num_idle_flows di ndpiReader) */
uint64_t last_time = 0;            /* tempo (ms) dell'ultimo pacchetto visto */
uint64_t last_idle_scan_time = 0;  /* tempo (ms) dell'ultima scansione */
flow_entry *idle_flows[IDLE_SCAN_BUDGET]; // array temporaneo dei flussi da rimuovere (1024)
u_int32_t num_idle_flows = 0; //quanti ne contiene
 
ip_stat *table = NULL;                 /* statistiche dell'intervallo corrente */
ip_stat *total_table = NULL;           /* statistiche cumulative, mai azzerate */
unsigned long total_pkts_global = 0; //pacchetti totali dell'intera cattura
pcap_t  *handle = NULL;
unsigned long byte_global = 0; //byte finestra globali
struct timeval start_time;
unsigned long byte_local  = 0;
long current_time = 0; // secondi tarscorsi
 
/* Flag impostato dal gestore di SIGINT: e' l'unica cosa che il gestore fa
 * (oltre a pcap_breakloop), perche' printf/free/exit non sono sicure
 * dentro un signal handler. La pulizia avviene nel main. */
volatile sig_atomic_t stop_richiesto = 0;
 
void get_local_ip(const char *interface);

void free_table(void);
void free_flow_table(void);
void init_ndpi(void);
int  drop_privileges(const char *username);
void sigproc(int sig);
void update_ip(const char *ip_srg, unsigned long bytes,
               const char *ip_dst, const char *app_protocol);
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);
void print_table(void);
void print_stats(double throughput_local, double dt);
void run_offline(const char *filename);
void print_final_stats(void);
void free_total_table(void);
void idle_scan(void);
void stampa_durata(void);
void info_argomenti_linea_comando(const char *prog);
 
void get_local_ip(const char *interface) {
    int fd;
    struct ifreq ifr; //struttura chiamata "interface request", è quella standard che il kernel usa per scambiare informazioni sulle interfacce di rete, inserisci il nome dell'interfaccia in ingresso e il kernel restituisce l'informazione richiesta
 
    fd = socket(AF_INET, SOCK_DGRAM, 0); //apre un socket UDP per avere un canale verso il livello di rete el kernel
    if (fd < 0) { perror("Errore apertura socket per IP"); return; }
 
    memset(&ifr, 0, sizeof(ifr));      /*azzero la struttura interface request in memoria*/
    ifr.ifr_addr.sa_family = AF_INET; //indico che voglio un indirizzo IPV4
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1); //copio il nome dell'interfaccia su cui effettuo la cattura nella struttura
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) { //modo per chiedere al kernel attraverso l'interfaccia se essa esiste e quale è il suo indirizzzo ip
        struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;//restituisce l'indirizzo in ifr_addr
        inet_ntop(AF_INET, &ipaddr->sin_addr, MIO_IP, INET_ADDRSTRLEN); //converte l'ip binario in stringa leggibile come la conosciamo e lo inserisce in MIO_IP
        printf("Indirizzo IP di %s trovato: %s\n", interface, MIO_IP); //lo stmapa
    } else {
        perror("Errore ioctl");
        strcpy(MIO_IP, "0.0.0.0");
    }
    close(fd);
}
 
void free_table(void) {
    ip_stat *current, *tmp;
    HASH_ITER(hh, table, current, tmp) {
        HASH_DEL(table, current);
        free(current);
    }
}
 
void free_flow_table(void) {
    flow_entry *fe, *tmp;
    HASH_ITER(hh, flow_table, fe, tmp) {
        HASH_DEL(flow_table, fe);
        if (fe->ndpi_flow) ndpi_free_flow(fe->ndpi_flow);
        free(fe);
    }
}
 
void init_ndpi(void) {
    /*
    funzione che viene utilizzata una sola volta nel main e server per far partire l'intero meccanismo nDPI.
    Crea l'oggetto centrale di nDPI (contiene tabelle protocolli e altre cose utili) con il primo comando e lo salva nel puntatore di ndpi_struct. NULL server per indicare che non cè niente da condividere con altri thread.
    Con l'ultimo comando viene finalizzato e fatto regolarente partire
    */
    ndpi_struct = ndpi_init_detection_module(NULL);
    if (!ndpi_struct) {
        fprintf(stderr, "Errore: ndpi_init_detection_module fallita\n");
        exit(1);
    }
 
    if (ndpi_finalize_initialization(ndpi_struct) != 0) {
        fprintf(stderr, "Errore: ndpi_finalize_initialization fallita\n");
        exit(1);
    }
 
    printf("nDPI %s inizializzato\n", ndpi_revision()); //ndpi_revision stampa la versione utilizzata di nDPI
}
 
int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw != NULL) {
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) return -1;
        fprintf(stderr, "Sicurezza: utente cambiato in %s\n", username);
    }
    return 0;
}
 
void print_final_stats(void) {
    printf("\n========== RIEPILOGO CATTURA ==========\n");
    printf("Pacchetti totali analizzati: %lu\n", total_pkts_global);
    printf("Totali per protocollo:\n");
    ip_stat *s;
    for (s = total_table; s != NULL; s = s->hh.next)
        printf("  %-20s %8lu pkt  %12lu Byte\n", s->protocol, s->pkts, s->bytes);
}
 
void free_total_table(void) {
    ip_stat *current, *tmp;
    HASH_ITER(hh, total_table, current, tmp) {
        HASH_DEL(total_table, current);
        free(current);
    }
}
 
void stampa_durata(void) {
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    printf("----------FINE CATTURA----------\n");
    printf("durata cattura[t = %ld]\n", end_time.tv_sec - start_time.tv_sec);
}
 
/* Gestore di SIGINT: solo operazioni async-signal-safe.
 * pcap_breakloop fa terminare pcap_dispatch/pcap_next_ex,
 * il flag fa uscire dai cicli; stampe e free avvengono nel main. */
void sigproc(int sig) {
    (void)sig;
    stop_richiesto = 1;
    if (handle) pcap_breakloop(handle);
}
 
/* Scansione dei flussi inattivi, con la logica di ndpiReader
 * (node_idle_scan_walker + rimozione differita):
 * Fase 1 - la tabella viene percorsa raccogliendo in idle_flows[] i flussi
 *          fermi da piu' di MAX_IDLE_TIME, fino a un massimo di
 *          IDLE_SCAN_BUDGET per scansione (costo limitato per chiamata);
 *          per i flussi non ancora classificati viene prima invocata
 *          ndpi_detection_giveup (come fa node_proto_guess_walker).
 * Fase 2 - i flussi raccolti vengono rimossi dalla tabella e liberati.
 * ndpiReader ripartisce i flussi su NUM_ROOTS alberi e ne scandisce uno a
 * rotazione; qui la tabella uthash e' unica, quindi la limitazione del
 * costo per scansione e' garantita dal solo budget. */
void idle_scan(void) {
    flow_entry *fe, *tmp;
 
    /* Fase 1: raccolta dei flussi idle (non si puo'/deve rimuovere
     * mentre si itera: stessa struttura a due fasi di ndpiReader) */
    HASH_ITER(hh, flow_table, fe, tmp) {
        if (num_idle_flows == IDLE_SCAN_BUDGET) break;
        if (fe->last_seen_ms + MAX_IDLE_TIME < last_time) {
            if (!fe->detection_done && fe->ndpi_flow)
                fe->detected_proto = ndpi_detection_giveup(ndpi_struct,
                                                           fe->ndpi_flow);
            idle_flows[num_idle_flows++] = fe;
        }
    }
 
    /* Fase 2: rimozione e liberazione dei flussi raccolti */
    while (num_idle_flows > 0) {
        fe = idle_flows[--num_idle_flows];
        HASH_DEL(flow_table, fe);
        if (fe->ndpi_flow) ndpi_free_flow(fe->ndpi_flow);
        free(fe);
    }
}
 
void run_offline(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
 
    handle = pcap_open_offline(filename, errbuf);
    if (!handle) { fprintf(stderr, "Errore apertura file: %s\n", errbuf); exit(1); }
 
    /* Il parsing assume frame Ethernet (header da 14 byte) */
    //controlla che i pacchetti siano frame ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Errore: il file non contiene frame Ethernet "
                        "(datalink %d non supportato)\n", pcap_datalink(handle));
        pcap_close(handle);
        exit(1);
    }
 
    struct bpf_program fp; 
    //setta il filtro bpf
    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Errore filtro BPF: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }
    pcap_freecode(&fp);//occupa la memoria occupata dal filtro bpf compilato
 
    struct pcap_pkthdr *header;
    const u_char *packet;
 
    struct timeval file_start   = {0, 0};
    struct timeval window_start = {0, 0};
    struct timeval prev_ts      = {0, 0};
    int first = 1;
 
    gettimeofday(&start_time, NULL);
 
    while (!stop_richiesto && pcap_next_ex(handle, &header, &packet) == 1) {
 
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
 
    /* Ultima finestra parziale: durata reale calcolata dal timestamp
     * dell'ultimo pacchetto, invece del valore fisso 1.0 */
    if (byte_global > 0) {
        double dt = (prev_ts.tv_sec  - window_start.tv_sec) +
                    (prev_ts.tv_usec - window_start.tv_usec) / 1e6;
        if (dt <= 0) dt = 1.0;
        current_time = window_start.tv_sec - file_start.tv_sec;
        print_stats(byte_local / dt, dt);
    }
    print_final_stats();
    pcap_close(handle);
    handle = NULL;
}
 
void update_ip(const char *ip_srg, unsigned long bytes,
               const char *ip_dst, const char *app_protocol) {
    ip_stat *s = NULL;
 
    /* --- tabella dell'intervallo (azzerata a ogni stampa) --- */
    HASH_FIND_STR(table, app_protocol, s);
    if (s == NULL) {
        s = calloc(1, sizeof(ip_stat));
        if (s == NULL) { fprintf(stderr, "Errore: memoria esaurita\n"); return; }
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
 
    /* --- tabella cumulativa (mai azzerata) --- */
    ip_stat *t = NULL;
    HASH_FIND_STR(total_table, app_protocol, t);
    if (t == NULL) {
        t = calloc(1, sizeof(ip_stat));
        if (t == NULL) { fprintf(stderr, "Errore: memoria esaurita\n"); return; }
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
    (void)args;   /* parametro richiesto dalla firma di libpcap, non usato */
 
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
 
    FlowKey key;
    memset(&key, 0, sizeof(FlowKey));   /* azzera anche i byte di padding */
    key.ia = ip_a; key.ib = ip_b;
    key.pa = port_a; key.pb = port_b;
    key.proto = l4_proto;
 
    /* Tempo del pacchetto in ms: usato da nDPI, dal campo last_seen_ms
     * e dalla scansione dei flussi idle (equivale a workflow->last_time
     * di ndpiReader: guida il tempo anche in modalita' offline) */
    uint64_t time_ms = (uint64_t)header->ts.tv_sec * 1000 +
                       header->ts.tv_usec / 1000;
    last_time = time_ms;
 
    flow_entry *fe = NULL;
    HASH_FIND(hh, flow_table, &key, sizeof(FlowKey), fe);
 
    if (fe == NULL) {
        fe = calloc(1, sizeof(flow_entry));
        if (fe == NULL) { fprintf(stderr, "Errore: memoria esaurita\n"); return; }
        fe->key = key;                  /* la chiave e' la struttura stessa */
 
        fe->ndpi_flow = calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
        if (fe->ndpi_flow == NULL) {
            fprintf(stderr, "Errore: memoria esaurita\n");
            free(fe);
            return;
        }
 
        fe->detection_done = 0;
        fe->detected_proto.proto.master_protocol = NDPI_PROTOCOL_UNKNOWN;
        fe->detected_proto.proto.app_protocol    = NDPI_PROTOCOL_UNKNOWN;
 
        HASH_ADD(hh, flow_table, key, sizeof(FlowKey), fe);
    }
 
    fe->last_seen_ms = time_ms;   /* il flusso e' vivo: aggiornato a ogni pacchetto */
 
    if (!fe->detection_done) {
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
            int soglia = (fe->key.proto == IPPROTO_TCP) ? 80 : 24;
 
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
 
    /* Pulizia periodica dei flussi idle (come in ndpi_process_packet di
     * ndpiReader): al massimo una scansione ogni IDLE_SCAN_PERIOD ms */
    if (last_idle_scan_time + IDLE_SCAN_PERIOD < last_time) {
        idle_scan();
        last_idle_scan_time = last_time;
    }
}
 
void print_table(void) {
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
    char errbuf[PCAP_ERRBUF_SIZE];
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
 
    /* L'utente deve specificare esattamente una modalita': -i oppure -f */
    if ((interface && pcap_file) || (!interface && !pcap_file)) {
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
 
    /* Inizializzazione comune alle due modalita' */
    signal(SIGINT, sigproc);
    gettimeofday(&start_time, NULL);
    init_ndpi();
 
    /* --- Modalita' Offline --- */
    if (pcap_file) {
        if (local_ip) {
            strncpy(MIO_IP, local_ip, INET_ADDRSTRLEN - 1);
            MIO_IP[INET_ADDRSTRLEN - 1] = '\0';
        } else {
            strcpy(MIO_IP, "0.0.0.0");
        }
        run_offline(pcap_file);
        free_flow_table();
        free_total_table();
        free_table();
        ndpi_exit_detection_module(ndpi_struct);
        stampa_durata();
        return 0;
    }
 
    /* --- Modalita' Live --- */
    get_local_ip(interface);
 
    handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
    if (!handle) { fprintf(stderr, "Errore pcap: %s\n", errbuf); return 1; }
 
    /* Il parsing assume frame Ethernet (header da 14 byte) */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Errore: interfaccia non Ethernet "
                        "(datalink %d non supportato)\n", pcap_datalink(handle));
        pcap_close(handle);
        return 1;
    }
 
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Errore filtro BPF: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);
 
    if (drop_privileges("nobody") != 0) {
        fprintf(stderr, "Errore: impossibile abbassare i privilegi, chiusura\n");
        pcap_close(handle);
        return 1;
    }
 
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
 
    /* Ciclo di cattura: termina quando sigproc imposta stop_richiesto */
    while (!stop_richiesto) {
        struct timeval now;
        do {
            pcap_dispatch(handle, -1, packet_handler, NULL);
            gettimeofday(&now, NULL);
        } while (!stop_richiesto &&
                 ((now.tv_sec  - t1.tv_sec)  * 1000000 +
                  (now.tv_usec - t1.tv_usec)) < (INTERVAL * 1000000));
 
        if (stop_richiesto) break;
 
        gettimeofday(&t2, NULL);
        double dt = (t2.tv_sec  - t1.tv_sec) +
                    (t2.tv_usec - t1.tv_usec) / 1e6;
        current_time = t2.tv_sec - start_time.tv_sec;
        print_stats(byte_local / dt, dt);
        t1 = t2;
    }
 
    /* Chiusura ordinata dopo Ctrl+C (ora raggiungibile) */
    fprintf(stderr, "\nChiusura in corso...\n");
    print_final_stats();
    pcap_close(handle);
    handle = NULL;
    free_flow_table();
    free_total_table();
    free_table();
    ndpi_exit_detection_module(ndpi_struct);
    stampa_durata();
    return 0;
}