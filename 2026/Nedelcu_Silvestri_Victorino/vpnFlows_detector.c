#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "include/ndpi_api.h"

/* Portato a 1518 per permettere a nDPI l'ispezione completa di certificati e handshake voluminosi */
#define DEFAULT_SNAPLEN 1518
#define MAX_HOSTS 1024
#define INTERVAL_SEC 10

/* Timeout breve che azzera il contesto nDPI per ricontare il flusso. */
#define FLOW_IDLE_SEC 120

/* Numero di pacchetti dopo il quale si forza ndpi_detection_giveup() */
#define NDPI_MAX_PKTS_TCP 24
#define NDPI_MAX_PKTS_UDP 10

/* DImensione tabella hash a concatenazione esterna per il lookup dei flussi */
#define FLOW_HASH_TABLE_SIZE 65536

/* Massimo numero di flussi salvabili permessi */
#define MAX_LIVE_FLOWS 65536

/* Dopo quanti intervalli senza traffico VPN un host marcato torna alla valutazione normale */
#define VPN_EXPIRY_INTERVALS 2

/* Soglia di calo dei flussi: se i flussi correnti scendono sotto questa frazione dei flussi precedenti, l'host diventa SUSPICIOUS */
#define DROP_RATIO_THRESHOLD 0.5f

/* Un host viene rimosso dalla stampa se resta con curr=0 e prev=0 per più di questo numero di intervalli consecutivi (evita di accumulare host morti). */
#define HOST_IDLE_EXPIRY 2

pcap_t *pd;
struct pcap_stat pcapStats;

int verbose = 0;
pcap_dumper_t *dumper = NULL;

/* Flag di stop condiviso con il signal handler e modalità di cattura. In offline il tempo è quello dei timestamp del pcap, in live è l'orologio di sistema */
static volatile sig_atomic_t stop_capture = 0;
static int is_offline = 0;

/* Offset del livello 3 calcolato dal datalink reale */
static int datalink_type = DLT_EN10MB;

/* Struttura globale del motore nDPI */
struct ndpi_detection_module_struct *ndpi_struct = NULL;

typedef struct {
    uint32_t ip;
    int current_flows;
    int prev_flows;
    int non_local;
    int zero_intervals;             /* intervalli consecutivi con curr=0 e prev=0 */
    float score;
    char last_detected_vpn[64];
    int vpn_from_db;                /* 1 se la detection proviene dal DB statico */
    int vpn_confirmed_ndpi;         /* 1 se nDPI ha confermato una detection del DB */
    time_t last_vpn_seen;           /* Ultimo momento in cui è stato visto traffico VPN da questo host */
    char last_app_proto[64];        /* protocollo applicativo (minor) rilevato da nDPI */
    char last_master_proto[64];     /* protocollo master (major) rilevato da nDPI */
} host_t;

/* Chiave del flusso come 5-tupla in forma canonica. */
typedef struct FlowKey {
    uint32_t ip_a;
    uint32_t ip_b;
    uint16_t port_a;
    uint16_t port_b;
    uint8_t protocol;
} FlowKey;

typedef struct FlowEntry {
    FlowKey key;

    /**L'endpoint a cui attribuire statistiche e detection è deciso UNA
     * VOLTA alla creazione e non dipende dal src del pacchetto corrente.
     * owner_ip è l'host locale (o il src del primo pacchetto se entrambi i lati
     * sono pubblici o entrambi privati), peer_ip/peer_port il lato remoto.
     */
    uint32_t owner_ip;
    uint32_t peer_ip;
    uint16_t peer_port;

    uint64_t packets;                   /* pacchetti visti (entrambe le direzioni) */
    uint64_t bytes;                     /* byte visti (entrambe le direzioni) */
    time_t last_seen;

    struct ndpi_flow_struct *ndpi_flow; /* Contesto di tracking nDPI per questo flusso */
    uint8_t detection_done;             /* 1 dopo classificazione o giveup */

    struct FlowEntry *next;             /* catena di collisione */
} FlowEntry;

static time_t last_tick = 0;

static host_t hosts[MAX_HOSTS];
static int host_count = 0;

static FlowEntry *flow_hash_table[FLOW_HASH_TABLE_SIZE];
static uint64_t total_flows = 0;   /* flussi attualmente vivi in tabella */

/* Struttura per il database delle firme VPN statiche */
typedef struct {
    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip_addr;
    uint8_t protocol;
    uint16_t port;
    char vpn_name[64];
} vpn_known_node_t;

/* Database statico legacy */
vpn_known_node_t vpn_nodes[] = {
    {"198.51.100.10", 0, IPPROTO_UDP, 51820, "ProtonVPN (WireGuard)"},
    {"198.51.100.11", 0, IPPROTO_UDP, 1194,  "ProtonVPN (OpenVPN UDP)"}
};

/* Prototipi di funzione */
static const int num_vpn_nodes = sizeof(vpn_nodes) / sizeof(vpn_nodes[0]);
static const char *vpn_proto_names[] = { "NordVPN", "OpenVPN", "WireGuard", "Tailscale", "ZeroTier" };
static const int num_vpn_proto_names = sizeof(vpn_proto_names) / sizeof(vpn_proto_names[0]);

void sigproc(int sig);
int drop_privileges_capabilities(void);
int is_private(uint32_t ip);
host_t* get_host(uint32_t ip);
host_t* find_host(uint32_t ip);
void update_stats(uint32_t owner_ip, uint32_t peer_ip);
void packetProcessingHandler(u_char *device_id, const struct pcap_pkthdr *h, const u_char *p);
void ip_network_order_conversion(uint32_t ip_addr, uint8_t *ip_bytes);
void update_scores(void);
void print_stats(void);
void printHelp(void);

char* detect_known_vpn_flow(uint32_t flow_dst_ip, uint8_t flow_proto, uint16_t flow_dst_port);
void init_vpn_database(void);
void init_ndpi(void);
void cleanup_ndpi(void);

void init_flow_table(void);
void cleanup_flow_table(void);
FlowEntry* get_or_create_flow(uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t p, int *is_new);
void maybe_tick(time_t now);

void sigproc(int sig) {
    static volatile sig_atomic_t called = 0;
    (void)sig;
    if (called) return;
    called = 1;
    stop_capture = 1;
    (void)!write(STDERR_FILENO, "Leaving...\n", 11);
    pcap_breakloop(pd);
}

int drop_privileges_capabilities(void) {
    cap_t caps;
    cap_value_t cap_list[] = {
        CAP_NET_RAW,
        CAP_NET_ADMIN
    };
    int num_caps = sizeof(cap_list) / sizeof(cap_list[0]);

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) return -1;

    caps = cap_get_proc();
    if (caps == NULL) return -1;

    if (cap_clear(caps) < 0) { cap_free(caps); return -1; }

    if (cap_set_flag(caps, CAP_EFFECTIVE, num_caps, cap_list, CAP_SET) < 0 ||
        cap_set_flag(caps, CAP_PERMITTED, num_caps, cap_list, CAP_SET) < 0) {
        cap_free(caps); return -1;
    }

    if (cap_set_proc(caps) < 0) { cap_free(caps); return -1; }
    cap_free(caps);

    struct passwd *pw = getpwnam("nobody");
    if (pw != NULL) {
        if (setgroups(0, NULL) != 0) {
            fprintf(stderr, "Warning: setgroups() failed\n");
        }
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
            fprintf(stderr, "Continuing with root user but limited capabilities\n");
        }
    }
    return 0;
}

void init_ndpi(void) {
    ndpi_struct = ndpi_init_detection_module(NULL);
    if (ndpi_struct == NULL) {
        fprintf(stderr, "Errore fatale: impossibile inizializzare nDPI.\n");
        exit(-1);
    }

    ndpi_finalize_initialization(ndpi_struct);
    printf("[+] Motore nDPI configurato e inizializzato correttamente.\n");
}

void cleanup_ndpi(void) {
    cleanup_flow_table();
    if (ndpi_struct) {
        ndpi_exit_detection_module(ndpi_struct);
        ndpi_struct = NULL;
    }
}

char* detect_known_vpn_flow(uint32_t flow_dst_ip, uint8_t flow_proto, uint16_t flow_dst_port) {
    (void)flow_dst_ip;
    for (int i = 0; i < num_vpn_nodes; i++) {
        if (flow_proto == vpn_nodes[i].protocol && flow_dst_port == vpn_nodes[i].port) {
            return vpn_nodes[i].vpn_name;
        }
    }
    return NULL;
}

void init_flow_table(void) {
    memset(flow_hash_table, 0, sizeof(flow_hash_table));
    total_flows = 0;
}

void cleanup_flow_table(void) {
    for (int i = 0; i < FLOW_HASH_TABLE_SIZE; i++) {
        FlowEntry *entry = flow_hash_table[i], *next;
        while (entry != NULL) {
            next = entry->next;
            if (entry->ndpi_flow) ndpi_flow_free(entry->ndpi_flow);
            free(entry);
            entry = next;
        }
        flow_hash_table[i] = NULL;
    }
    total_flows = 0;
}

/** Costruisce la chiave canonica: gli endpoint sono ordinati, quindi la direzione diretta e quella inversa producono la stessa chiave e lo stesso
 *  bucket (sostituisce il vecchio matching direct || reverse).
 */
static void make_flow_key(FlowKey *key, uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t proto) {
    if (s < d || (s == d && sp <= dp)) {
        key->ip_a = s;
        key->ip_b = d;
        key->port_a = sp;
        key->port_b = dp;
    } else {
        key->ip_a = d;
        key->ip_b = s;
        key->port_a = dp;
        key->port_b = sp;
    }
    key->protocol = proto;
}

/* Hash a rotazioni sulla 5-tupla */
static uint32_t hash_key(const FlowKey *key) {
    uint32_t h = 0;
    h ^= key->ip_a;
    h = (h << 13) | (h >> 19);
    h ^= key->ip_b;
    h = (h << 13) | (h >> 19);
    h ^= key->port_a;
    h = (h << 13) | (h >> 19);
    h ^= key->port_b;
    h = (h << 13) | (h >> 19);
    h ^= key->protocol;
    return h % FLOW_HASH_TABLE_SIZE;
}

static int keys_equal(const FlowKey *a, const FlowKey *b) {
    return (a->ip_a == b->ip_a &&
            a->ip_b == b->ip_b &&
            a->port_a == b->port_a &&
            a->port_b == b->port_b &&
            a->protocol == b->protocol);
}

FlowEntry* get_or_create_flow(uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t p, int *is_new) {
    FlowKey key;
    FlowEntry *entry;

    *is_new = 0;
    make_flow_key(&key, s, d, sp, dp, p);
    uint32_t idx = hash_key(&key);

    for (entry = flow_hash_table[idx]; entry != NULL; entry = entry->next) {
        if (keys_equal(&entry->key, &key)) return entry;
    }

    if (total_flows >= MAX_LIVE_FLOWS) {
        if (verbose) fprintf(stderr, "[!] Limite di %d flussi vivi raggiunto\n", MAX_LIVE_FLOWS);
        return NULL;
    }

    entry = calloc(1, sizeof(FlowEntry));
    if (entry == NULL) {
        fprintf(stderr, "Warning: Failed to allocate flow entry\n");
        return NULL;
    }

    entry->key = key;

    /* Owner/peer fissati alla creazione, sui valori NON normalizzati */
    if (is_private(s) && !is_private(d)) {
        entry->owner_ip = s; entry->peer_ip = d; entry->peer_port = dp;
    } else if (is_private(d) && !is_private(s)) {
        entry->owner_ip = d; entry->peer_ip = s; entry->peer_port = sp;
    } else {
        entry->owner_ip = s; entry->peer_ip = d; entry->peer_port = dp;
    }

    /* Dimensione della struttura chiesta alla libreria (è opaca e la sua dimensione dipende dalla build), allocatore nDPI e controllo del ritorno. */
    entry->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
    if (entry->ndpi_flow == NULL && verbose) {
        fprintf(stderr, "[!] Allocazione ndpi_flow_struct fallita\n");
    }

    entry->next = flow_hash_table[idx];
    flow_hash_table[idx] = entry;
    total_flows++;

    *is_new = 1;
    return entry;
}

/* Controllo IPv4 se definito come locale o privato */
int is_private(uint32_t ip) {
    uint8_t b[4];
    ip_network_order_conversion(ip, b);

    if (b[0] == 0) return 1;                                  /* 0.0.0.0/8 */
    if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return 1;

    if (b[0] == 127) return 1;                                /* Loopback */
    if (b[0] == 10) return 1;                                 /* 10/8 */
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 1;    /* 172.16/12 */
    if (b[0] == 192 && b[1] == 168) return 1;                 /* 192.168/16 */
    if (b[0] == 169 && b[1] == 254) return 1;                 /* Link-local (era 196.254) */
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return 1;   /* CGNAT 100.64/10 */
    if (b[0] >= 224) return 1;                                /* Multicast + riservati 240/4 */

    return 0; /* IP Pubblico / Globale */
}

/* Lookup-only: restituisce l'host se esiste, senza mai crearlo. */
host_t* find_host(uint32_t ip) {
    for (int i = 0; i < host_count; i++) {
        if (hosts[i].ip == ip) return &hosts[i];
    }
    return NULL;
}

host_t* get_host(uint32_t ip) {
    if (ip == 0x00000000 || ip == 0xFFFFFFFF) return NULL;

    host_t *existing = find_host(ip);
    if (existing) return existing;

    if (host_count < MAX_HOSTS) {
        memset(&hosts[host_count], 0, sizeof(host_t));
        hosts[host_count].ip = ip;
        return &hosts[host_count++];
    }
    return NULL;
}

/* Riceve owner/peer del flusso, non src/dst del pacchetto corrente. */
void update_stats(uint32_t owner_ip, uint32_t peer_ip) {
    host_t *h = get_host(owner_ip);
    if (!h) return;
    h->current_flows++;
    if (!is_private(peer_ip)) {
        h->non_local++;
    }
}

/**Il DB statico ha priorità sulla detection nDPI in qualsiasi ordine
 * arrivino, e un match del DB successivo a uno nDPI aggiorna comunque il nome
 * e imposta vpn_from_db (prima era impossibile, perché con score già a 1.0
 * il blocco interno non veniva mai più eseguito).
 */
void mark_flow(uint32_t ip, long tsec, const char *detection_source, const char *detected_vpn) {
    if (!is_private(ip)) return;

    host_t *h_src = get_host(ip);
    if (!h_src) return;

    int from_db = (strcmp(detection_source, "DB statico") == 0);

    h_src->last_vpn_seen = tsec;

    /* Una detection nDPI non può sovrascrivere una detection del DB... */
    if (h_src->vpn_from_db && !from_db) {
        h_src->vpn_confirmed_ndpi = 1;  /* ...ma la conferma */
        return;
    }

    h_src->score = 1.0f;
    strncpy(h_src->last_detected_vpn, detected_vpn, sizeof(h_src->last_detected_vpn) - 1);
    h_src->last_detected_vpn[sizeof(h_src->last_detected_vpn) - 1] = '\0';
    if (from_db) h_src->vpn_from_db = 1;
}

/* Applica il risultato nDPI (da process_packet o da giveup) al flusso. */
static void apply_ndpi_result(FlowEntry *f, ndpi_protocol ndpi_proto, long tsec) {
    char *app_name = ndpi_get_proto_by_id(ndpi_struct, ndpi_proto.proto.app_protocol);
    char *master_name = ndpi_get_proto_by_id(ndpi_struct, ndpi_proto.proto.master_protocol);

    /* I protocolli vanno sull'owner del flusso, non sul src del pacchetto. */
    host_t *h_proto = find_host(f->owner_ip);
    if (h_proto) {
        if (app_name != NULL && strcasecmp(app_name, "Unknown") != 0) {
            strncpy(h_proto->last_app_proto, app_name, sizeof(h_proto->last_app_proto) - 1);
            h_proto->last_app_proto[sizeof(h_proto->last_app_proto) - 1] = '\0';
        }
        if (master_name != NULL && strcasecmp(master_name, "Unknown") != 0) {
            strncpy(h_proto->last_master_proto, master_name, sizeof(h_proto->last_master_proto) - 1);
            h_proto->last_master_proto[sizeof(h_proto->last_master_proto) - 1] = '\0';
        }
    }

    if (verbose) {
        uint8_t ob[4], pb[4];
        ip_network_order_conversion(f->owner_ip, ob);
        ip_network_order_conversion(f->peer_ip, pb);
        fprintf(stdout, "[nDPI DEBUG] %u.%u.%u.%u -> %u.%u.%u.%u:%u | app=%s master=%s\n",
                ob[0], ob[1], ob[2], ob[3], pb[0], pb[1], pb[2], pb[3], f->peer_port,
                app_name ? app_name : "?", master_name ? master_name : "?");
    }

    for (int v = 0; v < num_vpn_proto_names; v++) {
        if (app_name != NULL && strcasecmp(app_name, vpn_proto_names[v]) == 0) {
            mark_flow(f->owner_ip, tsec, "nDPI", app_name);
            return;
        }
        if (master_name != NULL && strcasecmp(master_name, vpn_proto_names[v]) == 0) {
            mark_flow(f->owner_ip, tsec, "nDPI", master_name);
            return;
        }
    }
}

void discover_and_mark_flow(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort, uint16_t dstPort, uint8_t proto, long tsec, long tusec, const u_char *l3_ptr, u_int l3_len, u_int pkt_len) {
    int is_new = 0;
    FlowEntry *f = get_or_create_flow(srcIp, dstIp, srcPort, dstPort, proto, &is_new);
    if (!f) return;

    f->last_seen = (time_t)tsec;
    f->packets++;
    f->bytes += pkt_len;

    if (is_new) {
        update_stats(f->owner_ip, f->peer_ip);
    }

    /* STEP 1: Lookup nel database statico (usa peer_ip/peer_port del flusso, non dst del pacchetto corrente, che sui pacchetti di ritorno è il client) */
    char *detected_vpn = detect_known_vpn_flow(f->peer_ip, proto, f->peer_port);
    if (detected_vpn != NULL) {
        mark_flow(f->owner_ip, tsec, "DB statico", detected_vpn);
    }

    /* Interrogazione nDPI */
    if (f->ndpi_flow == NULL || f->detection_done) return;

    uint64_t time_ms = ((uint64_t)tsec * 1000) + (tusec / 1000);

    /* l3_ptr/l3_len arrivano già posizionati sul livello 3 in base al datalink reale (Ethernet, VLAN, Linux cooked, raw IP, loopback). */
    ndpi_protocol ndpi_proto = ndpi_detection_process_packet(ndpi_struct, f->ndpi_flow, (uint8_t *)l3_ptr, l3_len, time_ms, NULL);

    if (ndpi_proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN || ndpi_proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
        f->detection_done = 1;
        apply_ndpi_result(f, ndpi_proto, tsec);
        return;
    }

    /* Giveup dopo N pacchetti, altrimenti il flusso resta Unknown per sempre. */
    uint64_t limit = (proto == IPPROTO_TCP) ? NDPI_MAX_PKTS_TCP : NDPI_MAX_PKTS_UDP;
    if (f->packets >= limit) {
        ndpi_protocol guess = ndpi_detection_giveup(ndpi_struct, f->ndpi_flow);
        f->detection_done = 1;
        apply_ndpi_result(f, guess, tsec);
    }
}

/* Parsing del link layer. Ritorna 0 se ha individuato il livello 3, -1 altrimenti. */
static int link_layer_parse(const u_char *p, u_int caplen, u_int *l3_off, uint16_t *l3_type) {
    u_int off = 0;
    uint16_t type = 0;

    switch (datalink_type) {
        case DLT_EN10MB: {
            if (caplen < sizeof(struct ether_header)) return -1;
            const struct ether_header *eh = (const struct ether_header *)p;
            type = ntohs(eh->ether_type);
            off = sizeof(struct ether_header);

            /* Tag 802.1Q / 802.1ad: senza questo l'offset resta disallineato */
            int guard = 0;
            while ((type == ETHERTYPE_VLAN || type == 0x88A8 || type == 0x9100) && guard++ < 2) {
                if (caplen < off + 4) return -1;
                type = ntohs(*(const uint16_t *)(p + off + 2));
                off += 4;
            }
            break;
        }
        case DLT_LINUX_SLL: {
            if (caplen < 16) return -1;
            type = ntohs(*(const uint16_t *)(p + 14));
            off = 16;
            break;
        }
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2: {
            if (caplen < 20) return -1;
            type = ntohs(*(const uint16_t *)(p + 0));
            off = 20;
            break;
        }
#endif
        case DLT_NULL:
        case DLT_LOOP: {
            if (caplen < 4) return -1;
            uint32_t fam;
            memcpy(&fam, p, 4);
            if (datalink_type == DLT_LOOP) fam = ntohl(fam);
            if (fam == 2) type = ETHERTYPE_IP;
            else if (fam == 24 || fam == 28 || fam == 30) type = ETHERTYPE_IPV6;
            else return -1;
            off = 4;
            break;
        }
        case DLT_RAW: {
            if (caplen < 1) return -1;
            uint8_t ver = p[0] >> 4;
            if (ver == 4) type = ETHERTYPE_IP;
            else if (ver == 6) type = ETHERTYPE_IPV6;
            else return -1;
            off = 0;
            break;
        }
        default:
            return -1;
    }

    if (off > caplen) return -1;
    *l3_off = off;
    *l3_type = type;
    return 0;
}

/* Tick è isolato e può essere invocato anche senza traffico */
void maybe_tick(time_t now) {
    if (now == 0) return;
    if (last_tick == 0) { last_tick = now; return; }
    if (now - last_tick < INTERVAL_SEC) return;

    update_scores();
    print_stats();

    int active_hosts = 0;
    for (int i = 0; i < host_count; i++) {
        /* Scadenza VPN */
        if (hosts[i].score >= 1.0f &&
            (now - hosts[i].last_vpn_seen) >= (VPN_EXPIRY_INTERVALS * INTERVAL_SEC)) {
            hosts[i].score = 0.0f;
            hosts[i].vpn_from_db = 0;
            hosts[i].vpn_confirmed_ndpi = 0;
            memset(hosts[i].last_detected_vpn, 0, sizeof(hosts[i].last_detected_vpn));

            if (verbose) {
                uint8_t b[4];
                ip_network_order_conversion(hosts[i].ip, b);
                fprintf(stdout, "[i] VPN scaduta su Host %u.%u.%u.%u: stato riportato a NORMALE\n", b[0], b[1], b[2], b[3]);
            }
        }

        if (hosts[i].current_flows == 0 && hosts[i].prev_flows == 0) {
            hosts[i].zero_intervals++;
        } else {
            hosts[i].zero_intervals = 0;
        }

        if (hosts[i].zero_intervals > HOST_IDLE_EXPIRY && hosts[i].score < 1.0f) {
            if (verbose) {
                uint8_t b[4];
                ip_network_order_conversion(hosts[i].ip, b);
                fprintf(stdout, "[i] Host %u.%u.%u.%u rimosso: inattivo da %d intervalli\n", b[0], b[1], b[2], b[3], hosts[i].zero_intervals);
            }
            continue; /* non copiato -> eliminato dall'array */
        }

        hosts[i].prev_flows = hosts[i].current_flows;
        hosts[i].current_flows = 0;
        hosts[i].non_local = 0;

        if (active_hosts != i) hosts[active_hosts] = hosts[i];
        active_hosts++;
    }
    host_count = active_hosts;

    /* Purge dei flussi scaduti percorrendo le catene hash. Prima della rimozione si tenta un giveup, così i flussi corti ricevono comunque una classificazione best-effort. */
    for (int b = 0; b < FLOW_HASH_TABLE_SIZE; b++) {
        FlowEntry **pp = &flow_hash_table[b];
        while (*pp != NULL) {
            FlowEntry *entry = *pp;
            if (now - entry->last_seen > FLOW_IDLE_SEC) {
                if (!entry->detection_done && entry->ndpi_flow) {
                    ndpi_protocol g = ndpi_detection_giveup(ndpi_struct, entry->ndpi_flow);
                    entry->detection_done = 1;
                    apply_ndpi_result(entry, g, (long)entry->last_seen);
                }
                *pp = entry->next;              /* sgancio dalla catena */
                if (entry->ndpi_flow) {
                    ndpi_flow_free(entry->ndpi_flow);
                }
                free(entry);
                total_flows--;
            } else {
                pp = &entry->next;
            }
        }
    }

    last_tick = now;
}

void packetProcessingHandler(u_char *device_id, const struct pcap_pkthdr *h, const u_char *p) {
    (void)device_id;

    /* Se richiesto con -w, ogni pacchetto catturato viene salvato sul dump pcap. */
    if (dumper != NULL) pcap_dump((u_char *)dumper, h, p);

    u_int incl_len = h->caplen;
    u_int orig_len = h->len;

    /* Offline il tempo è quello del pcap, in live l'orologio reale. */
    time_t now = is_offline ? (time_t)h->ts.tv_sec : time(NULL);

    if (incl_len > orig_len) { maybe_tick(now); return; }

    u_int l3_off = 0;
    uint16_t l3_type = 0;

    if (link_layer_parse(p, incl_len, &l3_off, &l3_type) < 0) {
        maybe_tick(now);
        return;
    }

    /* ARP, IPv6 e qualunque altro ethertype NON vengono più passati a nDPI né usati per creare flussi fittizi con IP e porte a zero. */
    if (l3_type == ETHERTYPE_ARP) {
        if (verbose && incl_len >= l3_off + sizeof(struct ether_arp)) {
            struct ether_arp arph;
            uint32_t s_ip, d_ip;
            memcpy(&arph, p + l3_off, sizeof(struct ether_arp));
            memcpy(&s_ip, arph.arp_spa, 4);
            memcpy(&d_ip, arph.arp_tpa, 4);

            if (ntohs(arph.arp_op) == ARPOP_REQUEST) {
                char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
                struct in_addr sa = { .s_addr = s_ip }, da = { .s_addr = d_ip };
                inet_ntop(AF_INET, &sa, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &da, dst_ip_str, sizeof(dst_ip_str));
                fprintf(stdout, "[ARP] Request: Who has %s? -> Tell %s\n", dst_ip_str, src_ip_str);
            }
        }
        maybe_tick(now);
        return;
    }

    if (l3_type != ETHERTYPE_IP) {   /* IPv6 non gestito: niente flusso, niente nDPI */
        maybe_tick(now);
        return;
    }

    if (incl_len < l3_off + sizeof(struct ip)) {
        maybe_tick(now);
        return;
    }

    const struct ip *iph = (const struct ip *)(p + l3_off);
    uint32_t ip_header_len = (uint32_t)iph->ip_hl * 4;
    if (ip_header_len < sizeof(struct ip) || incl_len < l3_off + ip_header_len) {
        maybe_tick(now);
        return;
    }

    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint8_t protocol = iph->ip_p;
    uint16_t src_port = 0, dst_port = 0;

    if (protocol == IPPROTO_TCP) {
        if (incl_len < l3_off + ip_header_len + sizeof(struct tcphdr)) {
            maybe_tick(now);
            return;
        }
        const struct tcphdr *tcph = (const struct tcphdr *)(p + l3_off + ip_header_len);
        src_port = ntohs(tcph->th_sport);
        dst_port = ntohs(tcph->th_dport);
    } else if (protocol == IPPROTO_UDP) {
        if (incl_len < l3_off + ip_header_len + sizeof(struct udphdr)) {
            maybe_tick(now);
            return;
        }
        const struct udphdr *udph = (const struct udphdr *)(p + l3_off + ip_header_len);
        src_port = ntohs(udph->uh_sport);
        dst_port = ntohs(udph->uh_dport);
    } else {
        maybe_tick(now);
        return;
    }

    discover_and_mark_flow(src_ip, dst_ip, src_port, dst_port, protocol, (long)h->ts.tv_sec, (long)h->ts.tv_usec, p + l3_off, incl_len - l3_off, orig_len);

    maybe_tick(now);
}

int main(int argc, char *argv[]) {
    char *device = NULL, *bpfFilter = NULL, *writeFile = NULL;
    int c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int snaplen = DEFAULT_SNAPLEN;
    struct bpf_program fcode;
    struct stat s;

    while ((c = getopt(argc, argv, "hi:l:v:f:w:")) != -1) {
        switch (c) {
            case 'h': printHelp(); exit(0); break;
            case 'i': device = strdup(optarg); break;
            case 'l': snaplen = atoi(optarg); break;
            case 'v': verbose = atoi(optarg); break;
            case 'f': bpfFilter = strdup(optarg); break;
            case 'w': writeFile = strdup(optarg); break;
            default: printHelp(); exit(-1);
        }
    }

    if (snaplen <= 0) {
        snaplen = DEFAULT_SNAPLEN;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Please run this tool as superuser.\n");
        return -1;
    }

    if (device == NULL) {
        printf("ERROR: Missing -i\n");
        printHelp();
        return -1;
    }

    init_vpn_database();
    init_ndpi();
    init_flow_table();

    if (stat(device, &s) == 0) {
        is_offline = 1;
        if ((pd = pcap_open_offline(device, errbuf)) == NULL) {
            fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
            cleanup_ndpi();
            return -1;
        }
    } else {
        is_offline = 0;
        if ((pd = pcap_open_live(device, snaplen, 1, 500, errbuf)) == NULL) {
            fprintf(stderr, "pcap_open_live: %s\n", errbuf);
            cleanup_ndpi();
            return -1;
        }
    }

    datalink_type = pcap_datalink(pd);
    {
        u_int probe_off; uint16_t probe_type;
        u_char probe[64] = {0};
        if (link_layer_parse(probe, sizeof(probe), &probe_off, &probe_type) < 0 &&
            datalink_type != DLT_EN10MB && datalink_type != DLT_RAW &&
            datalink_type != DLT_NULL && datalink_type != DLT_LOOP &&
            datalink_type != DLT_LINUX_SLL) {
            fprintf(stderr, "Datalink non supportato: %s (%d)\n", pcap_datalink_val_to_name(datalink_type), datalink_type);
            pcap_close(pd);
            cleanup_ndpi();
            return -1;
        }
    }
    printf("[+] Datalink: %s (offset L3 calcolato dinamicamente)\n", pcap_datalink_val_to_name(datalink_type));

    if (bpfFilter != NULL) {
        if (pcap_compile(pd, &fcode, bpfFilter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pd));
        } else {
            if (pcap_setfilter(pd, &fcode) < 0) {
                fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(pd));
            }
            pcap_freecode(&fcode);
        }
    }

    /* Dump pcap opzionale (-w). Aperto da root PRIMA del drop dei privilegi,
     * così il file viene creato con i permessi giusti; l'utente 'nobody'
     * potrebbe non avere accesso in scrittura al percorso di destinazione. */
    if (writeFile != NULL) {
        dumper = pcap_dump_open(pd, writeFile);
        if (dumper == NULL) {
            fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(pd));
        } else {
            printf("[+] Dump dei pacchetti su: %s\n", writeFile);
        }
    }

    if (drop_privileges_capabilities() < 0) {
        fprintf(stderr, "Warning: Failed to drop privileges\n");
    }

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    if (is_offline) {
        pcap_loop(pd, -1, packetProcessingHandler, NULL);
    } else {
        /* pcap_dispatch ritorna anche allo scadere del read timeout (500 ms), quindi il tick avviene su base temporale reale anche quando sull'interfaccia non passa un singolo pacchetto. */
        while (!stop_capture) {
            int n = pcap_dispatch(pd, -1, packetProcessingHandler, NULL);
            if (n < 0) break; /* -1 errore, -2 pcap_breakloop */
            maybe_tick(time(NULL));
        }
    }

    update_scores();
    print_stats();

    if (dumper != NULL) {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
        dumper = NULL;
    }

    pcap_close(pd);
    cleanup_ndpi();

    free(device);
    free(bpfFilter);
    free(writeFile);

    return 0;
}

void ip_network_order_conversion(uint32_t ip_addr, uint8_t *ip_bytes) {
    uint32_t host_ip = ntohl(ip_addr);
    ip_bytes[0] = (host_ip >> 24) & 0xFF;
    ip_bytes[1] = (host_ip >> 16) & 0xFF;
    ip_bytes[2] = (host_ip >> 8) & 0xFF;
    ip_bytes[3] = host_ip & 0xFF;
}

void init_vpn_database(void) {
    for (int i = 0; i < num_vpn_nodes; i++) {
        if (inet_pton(AF_INET, vpn_nodes[i].ip_str, &vpn_nodes[i].ip_addr) != 1) {
            fprintf(stderr, "Errore nella conversione dell'IP: %s\n", vpn_nodes[i].ip_str);
        }
    }
    printf("[+] Database VPN statico inizializzato con %d nodi.\n", num_vpn_nodes);
}

void update_scores(void) {
    for (int i = 0; i < host_count; i++) {
        host_t *h = &hosts[i];
        if (h->score >= 1.0f) continue;   /* detection VPN attiva: score bloccato */

        if (h->current_flows == 0) h->score = 0.0f;
        else if (h->prev_flows == 0) h->score = 0.2f;
        else {
            float ratio = (float)h->current_flows / (float)h->prev_flows;
            h->score = (ratio < DROP_RATIO_THRESHOLD) ? 0.8f : 0.2f;
        }
    }
}

void print_stats(void) {
    printf("\n============================================ VPN DETECTION MONITOR ============================================\n");
    printf("%-16s | %-12s | %-12s | %-12s | %-10s | %-30s\n", "HOST IP", "CURR FLOWS", "PREV FLOWS", "NON-LOCAL", "SCORE", "NDPI DETECT [APP/MASTER]");
    printf("----------------------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < host_count; i++) {
        const host_t *h = &hosts[i];

        float display_score = h->score;
        char status_buf[128];

        const char *app = h->last_app_proto[0] ? h->last_app_proto : "?";
        const char *master = h->last_master_proto[0] ? h->last_master_proto : "?";

        if (h->vpn_from_db) {
            int confirmed = h->vpn_confirmed_ndpi || (h->last_app_proto[0] != '\0' || h->last_master_proto[0] != '\0');
            display_score = confirmed ? 1.0f : 0.8f;
            snprintf(status_buf, sizeof(status_buf), "%s: %s [%s/%s]", confirmed ? "DB+nDPI MATCH" : "DB MATCH", h->last_detected_vpn, app, master);
        } else if (h->score >= 1.0f) {
            snprintf(status_buf, sizeof(status_buf), "KNOWN VPN: %s [%s/%s]", h->last_detected_vpn, app, master);
        } else {
            snprintf(status_buf, sizeof(status_buf), "%s [%s/%s]", (h->score >= 0.8f) ? "SUSPICIOUS" : "NORMAL", app, master);
        }

        uint8_t b[4];
        ip_network_order_conversion(h->ip, b);
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

        printf("%-16s | %-12d | %-12d | %-12d | %5.1f%%     | %-30s\n", ip_str, h->current_flows, h->prev_flows, h->non_local, display_score * 100, status_buf);
    }
    printf("================================================================================================================\n\n");
}

void printHelp(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("Uso: vpnFlows_detector [-h] -i <device|path> [-w <path>] [-f <filter>] [-l <len>] [-v <1|2>]\n");
    printf("-h               [Print help]\n");
    printf("-i <device|path> [Device name or file path]\n");
    printf("-f <filter>      [pcap filter]\n");
    printf("-w <path>        [pcap write file]\n");
    printf("-l <len>         [Capture length]\n");
    printf("-v <mode>        [Verbose [1: verbose, 2: very verbose (print payload)]]\n");

    if(pcap_findalldevs(&devpointer, errbuf) == 0) {
        int i = 0;

        printf("\nAvailable devices (-i):\n");
        while (devpointer) {
            const char *descr = devpointer->description;

            if(descr) {
                printf(" %d. %s [%s]\n", i++, devpointer->name, descr);
            } else {
                printf(" %d. %s\n", i++, devpointer->name);
            }
            devpointer = devpointer->next;
        }
    }
}