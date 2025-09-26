#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <sys/wait.h>       // Per controllo su risultato di rrdtool
#include <errno.h>       

#define INTERVAL 60      // Intervallo di aggiornamento (in secondi) p.s.se si modifica bisogna allineare --step del db rrd
#define HASH_SIZE 64        // Dimensione ridotta visti i test in locale
#define SOGLIA 3      // Per generare un alert (molto bassa visti i test in locale)

// Strutture dati per IP e porte
struct PortNode {
    uint16_t port;
    struct PortNode *next;
    time_t last_seen;   
};

struct IPEntry {
    uint32_t ip;  
    struct PortNode *ports;
    struct IPEntry *next;  // Gestione collisioni (lista di IP con stesso hash)
    int alert_sent;    
    int port_count;
};

struct IPEntry *ip_table[HASH_SIZE];

int syn_count = 0;      
int keep_running = 1;
int debug = 0;

pcap_t *handle = NULL;

time_t start_time;

FILE *logfile;
struct bpf_program filter;      // Berkeley Packet Filter

// Handler per CTRL+C
void int_handler(int sig) {
    printf("\n[INFO] Interruzione ricevuta. Terminazione in corso...\n");
    keep_running = 0;
    if (handle != NULL) {
        pcap_breakloop(handle);     // Ferma pcap_dispatch        
    }
}

// Hash function
int hash_ip(uint32_t ip) {
    return ntohl(ip) % HASH_SIZE; // Converte in host byte order
}

void free_ip_table() {
    for (int i = 0; i < HASH_SIZE; i++) {
        struct IPEntry *entry = ip_table[i];
        while (entry != NULL) {
            // Libera la lista di porte
            struct PortNode *curr_port = entry->ports;
            while (curr_port != NULL) {
                struct PortNode *to_free_port = curr_port;
                curr_port = curr_port->next;
                free(to_free_port);
            }

            // Libera l'IPEntry
            struct IPEntry *to_free_entry = entry;
            entry = entry->next;
            free(to_free_entry);
        }
        ip_table[i] = NULL;
    }
}

// cleanup finale
void cleanup() {
    if (handle) pcap_close(handle);
    if (logfile) fclose(logfile);
    pcap_freecode(&filter);
    free_ip_table();
    printf("[INFO] Monitoraggio terminato correttamente.\n");
    return;
}

// Inserisce IP e porta nella struttura
void insert_ip_port(uint32_t ip, uint16_t port) {
    time_t now = time(NULL);

    char *time_str = ctime(&now);

    int index = hash_ip(ip);
    struct IPEntry *entry = ip_table[index];

    // Controlla se l'IP è già presente
    while (entry != NULL) {
        if (entry->ip == ip) {
            // IP già presente, controlla se la porta è già presente
            struct PortNode *p = entry->ports;
            while (p != NULL) {
                if (p->port == port) {      // La porta è già presente, aggiorna last_seen
                    p->last_seen = now;
                    return; 
                }
                p = p->next;
            }

            // Porta non presente, la aggiunge
            struct PortNode *new_port = malloc(sizeof(struct PortNode));
            if (!new_port) {
                perror("[ERRORE] malloc fallita.");
                return;
            }
            new_port->port = port;
            new_port->last_seen = now;
            new_port->next = entry->ports;

            entry->ports = new_port;
            entry->port_count++;

            // Controlla soglia
            if (entry->port_count >= SOGLIA && !entry->alert_sent) {
                entry->alert_sent = 1;      // Invia un solo allert per IP
                struct in_addr ip_addr; 
                ip_addr.s_addr = ip;
                printf("\a[ALLARME] %s Possibile port scan da %s\n", time_str, inet_ntoa(ip_addr));
                // Scrive anche sul file di log
                if (logfile != NULL) {
                    fprintf(logfile, " %s Possibile port scan da %s\n\n", time_str, inet_ntoa(ip_addr));
                    fflush(logfile); 
                } 
                else {
                    perror("[ERRORE] impossibile aprire il file di log.");
                }
            }
            return;
        }
        entry = entry->next;
    }

    // Nuovo IP, crea nuovo nodo
    struct IPEntry *new_entry = malloc(sizeof(struct IPEntry));
    if (!new_entry) {
        perror("[ERRORE] malloc fallita.");
        return;
    }

    new_entry->ip = ip;
    new_entry->ports = NULL;
    new_entry->next = ip_table[index]; 
    new_entry->port_count = 0;
    new_entry->alert_sent = 0;

    struct PortNode *new_port = malloc(sizeof(struct PortNode));
    if (!new_port) {
        perror("[ERRORE] malloc fallita");
        free(new_entry);    
        return;
    }
    new_port->port = port;
    new_port->last_seen = now;
    new_port->next = NULL;

    new_entry->ports = new_port;
    new_entry->port_count = 1;

    ip_table[index] = new_entry;
}

// Funzione di pulizia per rimuovere porte vecchie         
void cleanup_old_ports() {
    time_t now = time(NULL);
    for (int i = 0; i < HASH_SIZE; i++) {
        struct IPEntry *entry = ip_table[i];
        struct IPEntry *prev_entry = NULL; 
        
        while (entry != NULL) {
            struct PortNode *prev = NULL;
            struct PortNode *curr = entry->ports;

            while (curr != NULL) {
                if ((now - curr->last_seen) > INTERVAL) {
                    // Porta vecchia, rimuove
                    if (prev == NULL) {
                        entry->ports = curr->next;
                    } 
                    else {
                        prev->next = curr->next;
                    }
                    struct PortNode *to_free = curr;
                    curr = curr->next;
                    free(to_free);
                    entry->port_count--;
                } 
                else {
                    prev = curr;
                    curr = curr->next;
                }
            }

            // Se l'entry non ha più porte, la rimuove dalla tabella hash
            if (entry->port_count == 0) {
                struct IPEntry *to_free_entry = entry;
                if (prev_entry == NULL) {
                    // Entry è la prima nella lista della bucket hash
                    ip_table[i] = entry->next;
                } else {
                    prev_entry->next = entry->next;
                }
                entry = entry->next;
                free(to_free_entry);
            } else {
                prev_entry = entry;
                entry = entry->next;
            }
        }
    }
    if (debug) {
        printf("[DEBUG] Pulizia porte vecchie eseguita\n");
    } 
}

// Stampa IP -> porte (per debug)
void print_ip_table() {
    for (int i = 0; i < HASH_SIZE; i++) {
        struct IPEntry *entry = ip_table[i];
        while (entry != NULL) {
            struct in_addr ip_addr = { .s_addr = entry->ip };
            printf("[DEBUG] IP %s -> Porte: ", inet_ntoa(ip_addr));
            struct PortNode *p = entry->ports;
            while (p != NULL) {
                printf("%d ", p->port);
                p = p->next;
            }
            printf("\n");
            entry = entry->next;
        }
    }
}

// Funzione di gestione pacchetti
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    struct ip *ip_hdr = (struct ip *)(packet + 14);   // Saltia header Ethernet (14 byte)                         
    
    if (ip_hdr->ip_p != IPPROTO_TCP) return;        // Se non è TCP, esce

    // Salta header IP   
    struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));

    // Verifica flag: SYN attivo, ACK non attivo (già filtrato da BPF)
    if ((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK)) {
        
        uint32_t src_ip = ip_hdr->ip_src.s_addr;
        uint16_t dst_port = ntohs(tcp_hdr->th_dport);

        insert_ip_port(src_ip, dst_port);       // Salva IP e porta di destinazione
        syn_count++;
    }
}

int main(int argc, char *argv[]) {

    // Imposta handler CTRL+C
    struct sigaction sa;
    sa.sa_handler = int_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  
    sigaction(SIGINT, &sa, NULL);

    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        debug = 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Ricerca e scelta dell'interfaccia per lo sniffing                
    pcap_if_t *alldevs, *dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[ERRORE] pcap_findalldevs: %s\n", errbuf);
        cleanup();
        return 1;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "[ERRORE] Nessuna interfaccia trovata.\n");
        cleanup();
        return 1;
    }

    int i = 0;
    int choice = -1;

    printf("[INFO] Interfacce disponibili:\n");    
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d) %s\n", i, dev->name);
        i++;
    }

    printf("Inserisci il numero dell'interfaccia da usare: ");
    while (1) {
        int ret = scanf("%d", &choice);
        if (keep_running==0) {
            if (debug) {
                print_ip_table(); 
            } 
            pcap_freealldevs(alldevs);
            cleanup();
            return 0;
        } 
        if (ret == EOF || ret != 1) {
            perror("[ERRORE] Scanf.");
            pcap_freealldevs(alldevs);
            cleanup();
            return 1;
        }
        if ( choice < 0 || choice >= i) {
            printf("Input non valido. Riprova: ");
        } else {
            // Input corretto, esci dal ciclo
            break;
        }
    }

    // Prende l'interfaccia scelta
    dev = alldevs;
    for (i = 0; i < choice; i++) {
        dev = dev->next;
    }

    printf("[INFO] interfaccia selezionata: %s\n", dev->name);

    // Apre l'interfaccia
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERRORE] Impossibile aprire interfaccia: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        cleanup();
        return 1;
    }

    // Libera la lista delle interfacce
    pcap_freealldevs(alldevs);

    // Controlla se il file RRD esiste, altrimenti lo crea
    if (access("scan.rrd", F_OK) != 0) {
        printf("[INFO] Database RRD non trovato. Creazione...\n");

        int ret = system("rrdtool create scan.rrd --step 60 "
                         "DS:syn:GAUGE:120:0:U "   
                         "RRA:MAX:0.5:1:600 "
                         "RRA:MAX:0.5:5:720 "
                         "RRA:MAX:0.5:60:720 "
                        ); // 10 minuti (dati ogni 1 min), 1h (ogni 5 min), 1g (ogni 1h)

        if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {       
            fprintf(stderr, "[ERRORE] rrdtool ha fallito nella creazione del database RRD");
            if (WIFEXITED(ret)) {
                fprintf(stderr, " con codice %d", WEXITSTATUS(ret));
            }
            fprintf(stderr, ".\n");
            cleanup();
            return 1;
        }

    }

    // Apre il file in modalità append
    logfile = fopen("scan_alert.log", "a");
    if (logfile == NULL) {
        fprintf(stderr, "[ERRORE] Nell'apertura del file di log.\n");
        cleanup();
        return 1;
    }

    char filter_exp[] = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst portrange 1-1024";    // Controlla solo le porte tra 1 e 1024 

    // Compila e applica filtro BPF
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[ERRORE] Errore nella compilazione del filtro: %s\n", pcap_geterr(handle));
        cleanup();
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "[ERRORE] Errore nell'impostazione del filtro: %s\n", pcap_geterr(handle));
        cleanup();
        return 1;
    }

    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "[ERRORE] pcap_get_selectable_fd non supportato su questa piattaforma.\n");
        cleanup();
        return 1;
    }
    
    start_time = time(NULL);
    time_t last_cleanup = 0;

    printf("[INFO] Monitoraggio in corso. Premi CTRL+C per terminare...\n");


    // Loop 
    while (keep_running) {
        
        fd_set fdset;
        struct timeval timeout;

        FD_ZERO(&fdset);
        FD_SET(pcap_fd, &fdset);

        // Aspetta al massimo 1 secondo se non ci sono pacchetti
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int num = select(pcap_fd + 1, &fdset, NULL, NULL, &timeout);

        if (num == -1) {
            if (errno == EINTR) continue; // Interruzione da segnale
            perror("[ERRORE] Select.");
            break;
        } else if (num == 0) {
            // Nessun pacchetto
            sleep(1);
        } else {
            // Pacchetti pronti
            pcap_dispatch(handle, -1, packet_handler, NULL);    // Elabora tutti i pacchetti disponibili 
            if (debug) {
                printf("[DEBUG] Pacchetti SYN: %d\n", syn_count);
            } 
        } 
        
        //if (ret != 0){
            time_t now = time(NULL);
            char *time_str = ctime(&now);

            // Esegue pulizia   
            if (now - last_cleanup >= INTERVAL) {
                cleanup_old_ports();
                last_cleanup = now;
                if (debug) {
                    print_ip_table(); 
                } 
            }

            if (now - start_time >= INTERVAL) {
                if (keep_running) {
                    printf("[INFO] %s Pacchetti SYN: %d\n", time_str, syn_count);
                }

                // Aggiorna DB RRD
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "rrdtool update scan.rrd %ld:%d", (long)now, syn_count);
                int ret = system(cmd);
                if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
                    perror("[ERRORE] Update RRD fallito.");
                    if (WIFEXITED(ret)) {
                            fprintf(stderr, " con codice %d", WEXITSTATUS(ret));
                    }
                    fprintf(stderr, "\n");
                }

                // Reset contatore (GAUGE)
                syn_count = 0;
                
                char graph_cmd[512];
                snprintf(graph_cmd, sizeof(graph_cmd),
                    "rrdtool graph scan.png --start now-600 --end now "
                    "--title='Connessioni SYN (ultim1 10 minuti)' --vertical-label='SYN' "
                    "DEF:syn_max=scan.rrd:syn:MAX "
                    "LINE:syn_max#FF0000:'picco' > /dev/null");
                ret = system(graph_cmd);
                if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
                    perror("[ERRORE] Graph RRD fallito.");
                }
                
                start_time = now;
            }
       
    }

    if (debug) {
        print_ip_table(); 
    } 
    cleanup();
    return 0;
}
