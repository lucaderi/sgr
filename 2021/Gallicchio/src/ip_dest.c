#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <signal.h>
#include <arpa/inet.h>

#include <roaring.h>
#include <ip_dest_hash_table.h>

#define ARG_MAX_LEN 256
#define HASH_TABLE_CAP 128

typedef struct ip_dest_hash_table* HashTable;

/**
 * \brief Controlla se la stringa str è un numero intero e lo salva in *n in caso lo fosse.
 * \return 1 in caso di successo,
 *         0 se str == NULL || n == NULL (setta errno a EINVAL), se str non è
 *         un numero intero, o in caso di overflow/underflow (setta errno a ERANGE).
 */
static inline int isNumber(const char* str, long int* n);

// Funzione eseguita quando vengono ricevuti i segnali SIGALRM e SIGINT
static void signal_handler(int sig);

// Funzione chiamata su ogni pacchetto catturato
static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);

// Funzione di comparazione usata da qsort
static int compar(const void* arg_1, const void* arg_2);

/**
 * \brief Stampa su stdout le possibili opzioni da passare al programma.
 */
static void printUsage(void);

// Lo handle per la cattura dei pacchetti
static pcap_t* handle = NULL;

// Struttura passata come argomento a pcap_loop
struct user_info {
    HashTable hash_table;
    int v;
};

int main(int argc, char* argv[]) {
    short int h = 0, i = 0, p = 0, t = 0, v = 0;
    char arg[ARG_MAX_LEN+1];
    char *h_str = NULL, *m_str = NULL, *s_str = NULL;
    long int hours = 0, minutes = 0, seconds = 0;
    unsigned int tot_sec = 0;
    
    char c;
    while((c = getopt(argc, argv, ":hi:t:p:v")) != -1) {
        switch(c) {
            case 'h':
                if(h) {
                    fprintf(stderr, "Errore: opzione -h passata più di una volta.\n");
                    return -1;
                }
                h = 1;
                if(i|p) {
                    fprintf(stderr, "Errore: scegliere una sola tra le opzioni -h, -i, -p.\n");
                    return -1;
                }
                break;
            case 'i':
                if(i) {
                    fprintf(stderr, "Errore: opzione -i passata più di una volta.\n");
                    return -1;
                }
                i = 1;
                if(h|p) {
                    fprintf(stderr, "Errore: scegliere una sola tra le opzioni -h, -i, -p.\n");
                    return -1;
                }
                if(strlen(optarg) > ARG_MAX_LEN) {
                    fprintf(stderr, "Errore: nome interfaccia troppo lungo.\n");
                    return -1;
                }
                strncpy(arg, optarg, ARG_MAX_LEN+1);
                break;
            case 't':
                if(t) {
                    fprintf(stderr, "Errore: opzione -t passata più di una volta.\n");
                    return -1;
                }
                if(!i) {
                    fprintf(stderr, "Errore: indicare con -i il nome dell'interfaccia prima dell'opzione -t.\n");
                    return -1;
                }
                h_str = strtok(optarg, ":");
                m_str = strtok(NULL, ":");
                s_str = strtok(NULL, ":");
                if(h_str == NULL || m_str == NULL || s_str == NULL) {
                    fprintf(stderr, "Errore: argomento dell'opzione -t non valido.\n");
                    return -1;
                }
                if(!isNumber(h_str, &hours) || !isNumber(m_str, &minutes) || !isNumber(s_str, &seconds)) {
                    fprintf(stderr, "Errore: argomento dell'opzione -t non valido.\n");
                    return -1;
                }
                if(hours < 0 || minutes < 0 || seconds < 0 || minutes >= 60 || seconds >= 60) {
                    fprintf(stderr, "Errore: argomento dell'opzione -t non valido.\n");
                    return -1;
                }
                tot_sec = (unsigned int) hours*3600 + (unsigned int) minutes*60 + (unsigned int) seconds;
                break;
            case 'p':
                if(p) {
                    fprintf(stderr, "Errore: opzione -p passata più di una volta.\n");
                    return -1;
                }
                p = 1;
                if(h|i) {
                    fprintf(stderr, "Errore: scegliere una sola tra le opzioni -h, -i, -p.\n");
                    return -1;
                }
                if(strlen(optarg) > ARG_MAX_LEN) {
                    fprintf(stderr, "Errore: nome file pcap troppo lungo.\n");
                    return -1;
                }
                strncpy(arg, optarg, ARG_MAX_LEN+1);
                break;
            case 'v':
                if(v) {
                    fprintf(stderr, "Errore: opzione -v passata più di una volta.\n");
                    return -1;
                }
                v = 1;
                if(h) {
                    fprintf(stderr, "Errore: opzione -v non consentita con -h.\n");
                    return -1;
                }
                if(!(i|p)) {
                    fprintf(stderr, "Errore: usare l'opzione -i o -p prima dell'opzione -v.\n");
                    return -1;
                }
                break;
            case ':':
                fprintf(stderr, "Errore: argomento dell'opzione -%c mancante.\n", optopt);
                return -1;
            case '?':
                fprintf(stderr, "Errore: opzione -%c non riconosciuta.\n", optopt);
                return -1;
            default:
                break;
        }
    }
    if((h|i|p) == 0) {
        fprintf(stderr, "Errore: scegliere una tra le opzioni -h, -i, -p.\n");
        return -1;
    }
    
    if(h) {
        printUsage();
        return 0;
    }
    
    HashTable hash_table = NULL;
    struct bpf_program filter;
    // Filtro: legge solo i pacchetti con IPv4
    char filter_exp[] = "ether proto 0x0800";
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if(i) {
        // Packet capture handle
        int snaplen = 128;
        int promisc = 1;
        int to_ms = 10000;
        handle = pcap_open_live(arg, snaplen, promisc, to_ms, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "%s.\n", errbuf);
            return -1;
        }
    } else {
        // p
        handle = pcap_open_offline(arg, errbuf);
        if(handle == NULL) {
            fprintf(stderr, "%s.\n", errbuf);
            return -1;
        }
    }
    
    // Compila e setta il filtro
    if(pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "%s.\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("%s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    
    // Inizializza la tabella hash
    if((hash_table = ip_dest_hash_table_new(HASH_TABLE_CAP)) == NULL) {
        fprintf(stderr, "Errore: memoria insufficiente.\n");
        pcap_close(handle);
        return -1;
    }
    
    // Imposta i segnali SIGALARM e SIGINT
    struct sigaction act;
    struct sigaction sigalrm_old_act;
    struct sigaction sigint_old_act;
    act.sa_handler = signal_handler;
    sigset_t sa_mask;
    sigemptyset(&sa_mask);
    sigaddset(&sa_mask, SIGALRM);
    sigaddset(&sa_mask, SIGINT);
    act.sa_mask = sa_mask;
    act.sa_flags = 0;
    if(sigaction(SIGALRM, &act, &sigalrm_old_act) == -1 || sigaction(SIGINT, &act, &sigint_old_act) == -1) {
        perror(NULL);
        pcap_close(handle);
        ip_dest_hash_table_free(hash_table);
        return -1;
    }
    
    // Legge i pacchetti
    if(v) {
        printf("Avvio della cattura dei pacchetti...\n\n");
        printf("%-15s -> %s\n", "src_ip", "dest_ip");
        printf("----------------------------------\n");
    }
    
    // Avvia il timer
    alarm(tot_sec);
    
    struct user_info info = {hash_table, v};
    pcap_loop(handle, 0, packet_handler, (u_char *) &info);
    
    // Chiude lo handle
    pcap_close(handle);
    handle = NULL;
    
    if(v) {
        printf("\nCattura dei pacchetti terminata.\n\n");
        fflush(stdout);
    }
    
    // Ripristina le vecchie azioni per i segnali SIGALARM e SIGINT
    if(sigaction(SIGALRM, &sigalrm_old_act, NULL) == -1 || sigaction(SIGINT, &sigint_old_act, NULL) == -1) {
        perror(NULL);
        ip_dest_hash_table_free(hash_table);
        return -1;
    }
    
    struct ip_dest_hash_table_node** arr = NULL;
    size_t arr_size;
    switch(ip_dest_hash_table_get_array(hash_table, &arr, &arr_size)) {
        case -1:
            // hash_table == NULL || arr == NULL || arr_size == NULL
            fprintf(stderr, "Errore: uno o più argomenti passati alla funzione ip_dest_hash_table_get_array non sono validi.\n");
            ip_dest_hash_table_free(hash_table);
            return -1;
        case -2:
            // Non è stato possibile allocare la memoria
            fprintf(stderr, "Errore: memoria insufficiente.\n");
            ip_dest_hash_table_free(hash_table);
            return -1;
        default:
            break;
    }
    
    // Ordina il vettore
    qsort(arr, arr_size, sizeof(struct ip_dest_hash_table_node*), compar);
    
    // Stampa i top host per numero di destinazioni
    printf("%-4s %-15s %s\n", "#", "src_ip", "#destinations");
    printf("----------------------------------\n");
    for(int j = 0; j < arr_size; j++) {
        if(i == 10) break;
        struct in_addr src_ip = { arr[j]->src_ip };
        char src_ip_str[16];
        strncpy(src_ip_str, inet_ntoa(src_ip), 16);
        printf("%-4d %-15s %llu\n", j+1, src_ip_str, roaring_bitmap_get_cardinality(arr[j]->destinations));
    }
    
    // Libera dalla memoria la tabella hash e il vettore arr
    ip_dest_hash_table_free(hash_table);
    free(arr);
    
    return 0;
}

static inline int isNumber(const char* str, long int* n) {
    if (str == NULL || n == NULL) {
        errno = EINVAL;
        return 0;
    }
    char* endptr = NULL;
    errno=0;
    long int val = strtol(str, &endptr, 10);
    if (errno == ERANGE) return 0;
    if (*str != '\0' && *endptr == '\0') {
        *n = val;
        return 1;
    }
    return 0;
}

static void signal_handler(int sig) {
    if(handle != NULL) pcap_breakloop(handle);
}

static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    struct user_info* info = (struct user_info*) user;
    HashTable hash_table = info->hash_table;
    int v = info->v;
    
    int eth_header_len = 14;
    // Il pacchetto deve contenere almeno l'intestazione ethernet e i primi 20 byte di quella IP
    if(h->caplen < eth_header_len + 20) {
        fprintf(stderr, "Errore: pacchetto catturato troppo breve.\n");
        return;
    }
    // L'indirizzo IP sorgente si trova a 20 byte di distanza a partire dall'inizio dell'intestazione IP
    const u_char* src_ip_ptr = bytes + eth_header_len + 12;
    // L'indirizzo IP destinazione si trova a 4 byte di distanza dall'inidirizzo IP sorgente
    const u_char* dest_ip_ptr = src_ip_ptr + 4;
    struct in_addr* src_ip = (struct in_addr*) src_ip_ptr;
    struct in_addr* dest_ip = (struct in_addr*) dest_ip_ptr;
    
    switch(ip_dest_hash_table_insert(hash_table, src_ip->s_addr, dest_ip->s_addr)) {
        case -1:
            // hash_table == NULL
            fprintf(stderr, "Errore: l'argomento passato alla funzione ip_dest_hash_table_insert non è valido.\n");
            pcap_breakloop(handle);
            return;
        case -2:
            // Non è stato possibile allocare la memoria
            fprintf(stderr, "Errore: memoria insufficiente.\n");
            pcap_breakloop(handle);
            return;
        default:
            break;
    }
    
    if(v) {
        char src_ip_str[16];
        char dest_ip_str[16];
        strncpy(src_ip_str, inet_ntoa(*src_ip), 16);
        strncpy(dest_ip_str, inet_ntoa(*dest_ip), 16);
        printf("%-15s -> %s\n", src_ip_str, dest_ip_str);
    }
}

static int compar(const void* arg_1, const void* arg_2) {
    struct ip_dest_hash_table_node* elem_1 = *(struct ip_dest_hash_table_node**) arg_1;
    struct ip_dest_hash_table_node* elem_2 = *(struct ip_dest_hash_table_node**) arg_2;
    return (int) roaring_bitmap_get_cardinality(elem_2->destinations) - (int) roaring_bitmap_get_cardinality(elem_1->destinations);
}

static void printUsage() {
    printf("Usage:\n");
    printf("./ip_dest -h\n");
    printf("./ip_dest -i network_interface [-t hh:mm:ss] [-v]\n");
    printf("./ip_dest -p pcap_file [-v]\n");
}
