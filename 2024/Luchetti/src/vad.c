/*
 *
 * Prerequisite
 * sudo apt-get install libpcap-dev
 * gcc pcount.c -o pcount -lpcap
 *
 * PER AVVIARE IL PROGRAMMA IN MODALITA' "ASCOLTO" DEVE ESSERCI STATO LO SCAMBIO DI CHIAVI PUBBLICHE TRA COMPUTER E MIKROTIK
 * 1)generare chiave su pc:
 *      ssh-keygen -t rsa -b 4096 -f ~/.ssh/mikrotik_rsa -N ""
 * 2)condividerla con Mikrotik
 *      scp ~/.ssh/mikrotik_rsa.pub admin@ip:/
 * 3)aggiungere la chiave pubblica all'account:
 *        ssh admin@ip
 *       /user ssh-keys import public-key-file=mikrotik_rsa.pub user="MIKROTIK_USER"
 *
 * PRIMA DI LANCIARE IL PROGRAMMA MODIFICARE LE VARIABILI 
*/

#include <pcap/pcap.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <time.h>
#include <dirent.h>
#include <netinet/udp.h>

/* Variabili globali */
pcap_t  *pd;
static struct timeval firstPacketTime, lastPacketTime;
static struct timeval intervalStartTime;
unsigned long long numPkts = 0, numBytes = 0;
unsigned long long intervalPkts = 0, intervalBytes = 0;
int mode;
unsigned long long PACKET_THRESHOLD=3000; // Soglia pacchetti/sec oltre il quale è considerato attacco DDOS

//variabili da modificare per adattare il codice alle esigenze
#define FILE_TO_CHECK "./sniffer.pcap"          //specificare il nome del file che riceveremo
#define SLEEP_INTERVAL 60                      // tempo in secondi tra una scansione e la successiva 
#define PACKET_TYPE IPPROTO_UDP                 //tipo di pacchetti da analizzare in base all'attacco da cui vogliamo difenderci

#define REMOTE_FILE "./sniffer.pcap"            // Percorso del file remoto su MikroTik
#define LOCAL_FILE "."                          // File locale
#define MIKROTIK_USER "admin"                   // Nome utente MikroTik
#define MIKROTIK_IP "192.168.100.154"           // Indirizzo IP del firewall MikroTik
#define SSH_KEY_PATH "../../../../mtik_rsa"     // Percorso della chiave SSH

#define RRD_SIZE 100                            // Numero massimo di indirizzi IP di destinazione da tracciare

// Struttura per tracciare IP di destinazione, porta e il conteggio dei pacchetti
struct simple_rrd {
    char destination_ips[RRD_SIZE][INET_ADDRSTRLEN];  // Array di IP di destinazione
    int destination_ports[RRD_SIZE];                 // Array di porte di destinazione
    int packet_counts[RRD_SIZE];                     // Contatori per ogni IP+porta
    int current_index;                               // Indice corrente per gestione circolare
};

// Inizializza la struttura RRD
struct simple_rrd traffic_rrd = { .current_index = 0 };

// Funzione per aggiornare la RRD con un nuovo IP e porta di destinazione o incrementare il contatore esistente
void update_rrd(char *dest_ip, int dest_port) {
    int i;

    for (i = 0; i < RRD_SIZE; i++) {
        if (strcmp(traffic_rrd.destination_ips[i], dest_ip) == 0 && traffic_rrd.destination_ports[i] == dest_port) {
            traffic_rrd.packet_counts[i]++;
            return;
        }
    }

    // Se l'indirizzo IP e la porta non sono presenti, li aggiungiamo nella posizione corrente
    strcpy(traffic_rrd.destination_ips[traffic_rrd.current_index], dest_ip);
    traffic_rrd.destination_ports[traffic_rrd.current_index] = dest_port;
    traffic_rrd.packet_counts[traffic_rrd.current_index] = 1;  // Inizializza il contatore a 1

    // Aggiorna l'indice corrente
    traffic_rrd.current_index = (traffic_rrd.current_index + 1) % RRD_SIZE;
}

// Funzione per azzerare i contatori nella RRD
void reset_rrd() {
    for (int i = 0; i < RRD_SIZE; i++) {
        traffic_rrd.packet_counts[i] = 0;
    }
}


// Funzione per scambiare due elementi della RRD
void swap_rrd(int i, int j) {
    char temp_ip[INET_ADDRSTRLEN];
    int temp_port, temp_count;

    // Scambia IP
    strcpy(temp_ip, traffic_rrd.destination_ips[i]);
    strcpy(traffic_rrd.destination_ips[i], traffic_rrd.destination_ips[j]);
    strcpy(traffic_rrd.destination_ips[j], temp_ip);

    // Scambia porte
    temp_port = traffic_rrd.destination_ports[i];
    traffic_rrd.destination_ports[i] = traffic_rrd.destination_ports[j];
    traffic_rrd.destination_ports[j] = temp_port;

    // Scambia contatori
    temp_count = traffic_rrd.packet_counts[i];
    traffic_rrd.packet_counts[i] = traffic_rrd.packet_counts[j];
    traffic_rrd.packet_counts[j] = temp_count;
}

// Funzione per ordinare la RRD in base agli indirizzi IP
void sort_rrd_by_ip() {
    int i, j;
    for (i = 0; i < RRD_SIZE - 1; i++) {
        for (j = i + 1; j < RRD_SIZE; j++) {
            // Confronta gli indirizzi IP alfabeticamente
            if (strcmp(traffic_rrd.destination_ips[i], traffic_rrd.destination_ips[j]) > 0) {
                // Se l'IP i è maggiore di j, scambiamo i due elementi
                swap_rrd(i, j);
            }
        }
    }
}


// Funzione per stampare le statistiche sugli IP, porte e conteggi dei pacchetti
void print_rrd() {
    int i;
    // Ordina le statistiche per IP
    sort_rrd_by_ip();

    printf("\nStatistiche traffico:\n");

    // Variabile per tracciare l'ultimo IP stampato
    char last_ip[INET_ADDRSTRLEN] = "";

    for (i = 0; i < RRD_SIZE; i++) {
        // Stampiamo solo le righe con contatori > 0
        if (traffic_rrd.packet_counts[i] > 0) {
            // Se l'IP corrente è diverso dall'ultimo stampato
            if (strcmp(last_ip, traffic_rrd.destination_ips[i]) != 0) {
                // Stampa il nuovo IP
                printf("IP: %s:\n", traffic_rrd.destination_ips[i]);
                // Aggiorna l'ultimo IP stampato
                strcpy(last_ip, traffic_rrd.destination_ips[i]);
            }

            // Stampa porta e pacchetti relativi a questo IP
            printf("\tPorta: %d, Pacchetti: %d\n", traffic_rrd.destination_ports[i], traffic_rrd.packet_counts[i]);
        }
    }
}


/* Funzione per l'invio di email */
void send_ddos_alert(double pkt_per_sec, double bytes_per_sec) {
    char command[256];
    snprintf(command, sizeof(command),"echo 'WARNING: Possible DDoS detected! %.1f packets/sec or %.2f bytes/sec' | mail -s 'DDoS Alert' aluchetti@toplan.it", pkt_per_sec, bytes_per_sec);
    system(command);
}

//funzione utilizzata per controllare le soglie 
void check_for_ddos(u_int64_t diff_packets, u_int64_t diff_bytes, float deltaSec) {
    double pkt_per_sec = (double)diff_packets / deltaSec;
    double bytes_per_sec = (double)diff_bytes / deltaSec;

    if (pkt_per_sec > PACKET_THRESHOLD) {
        printf("\n\t\t\tWARNING: Possible DDoS detected! %.1f packets/sec or %.2f bytes/sec\n", pkt_per_sec, bytes_per_sec);
        send_ddos_alert(pkt_per_sec, bytes_per_sec);
    }
    else {
        printf("No DDOS attack detected! %.1f packets/sec or %.2f bytes/sec\n", pkt_per_sec, bytes_per_sec);
    }
}


//funzione usata per stampare le statistiche in ogni intervallo
void print_interval_stats(float deltaSec) {
    
    if(mode!=2){
        printf("\nInterval duration: %.2f seconds\n", deltaSec);
        printf("Packets in interval: %llu, Bytes in interval: %llu\n", intervalPkts, intervalBytes);
        printf("Packets/sec: %.1f, Bytes/sec: %.2f KB/sec\n",(double)intervalPkts / deltaSec, (double)intervalBytes / (deltaSec * 1000));
        check_for_ddos(intervalPkts, intervalBytes, deltaSec);
    }else{
        if((double)intervalPkts / deltaSec>PACKET_THRESHOLD){
            PACKET_THRESHOLD=(double)intervalPkts / deltaSec;
        }
    }

    intervalPkts = 0;
    intervalBytes = 0;
}

//funzione che analizza ogni pacchetto
void dummyProcessPacket(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p) {
    struct ether_header ehdr;
    struct ip *iphdr;
    u_short eth_type;
    float deltaSec;

    // Copia l'intestazione Ethernet
    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);

    // Verifica se il pacchetto è IP (EtherType 0x0800)
    if (eth_type == ETHERTYPE_IP) {
        iphdr = (struct ip *)(p + sizeof(struct ether_header));

        // Controlla se è un pacchetto UDP
        if (iphdr->ip_p == PACKET_TYPE) {
            numPkts++;
            numBytes += h->len;

            intervalPkts++;  // Conta pacchetti nell'intervallo
            intervalBytes += h->len; // Conta byte nell'intervallo

            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iphdr->ip_dst, dest_ip, sizeof(dest_ip));

                
            int dest_port = 0;

            struct udphdr *udph = (struct udphdr *)(p + sizeof(struct ether_header) + sizeof(struct ip));
            dest_port = ntohs(udph->uh_dport);  // Porta di destinazione UDP
            
            // Aggiorna la struttura RRD con il solo IP di destinazione e incrementa il contatore
            update_rrd(dest_ip, dest_port);

            // Salva il timestamp del primo pacchetto
            if (numPkts == 1) {
                firstPacketTime = h->ts;  // Tempo del primo pacchetto
                intervalStartTime = h->ts; // Inizio del primo intervallo
            }

            // Calcola il tempo trascorso dall'inizio dell'intervallo
            deltaSec = (h->ts.tv_sec + h->ts.tv_usec / 1000000.0) - (intervalStartTime.tv_sec + intervalStartTime.tv_usec / 1000000.0);

            // Se l'intervallo di 30 secondi è trascorso
            if (deltaSec >= 30.0) {
                // Stampa le statistiche per l'intervallo e verifica l'attacco DDoS
                print_interval_stats(deltaSec);

                // Resetta l'inizio dell'intervallo
                intervalStartTime = h->ts;
            }

            // Salva il timestamp dell'ultimo pacchetto
            lastPacketTime = h->ts;
        }
    }
}

//Funzione che stampa le statistiche finali
void print_final_stats() {
    float totalCaptureTime, finalIntervalTime;

    if (numPkts == 0) {
        switch (PACKET_TYPE) {
        case IPPROTO_ICMP:
            printf("Nessun pacchetto di tipo ICMP trovato.\n");
            break;
        case IPPROTO_TCP:
            printf("Nessun pacchetto di tipo TCP trovato.\n");
            break;
        case IPPROTO_UDP:
            printf("Nessun pacchetto di tipo UDP trovato.\n");
            break;
        default:
            printf("Nessun pacchetto di tipo sconosciuto trovato.\n");
            break;
        }
        return;
    }
    // Calcola il tempo totale di cattura
    totalCaptureTime = (lastPacketTime.tv_sec + lastPacketTime.tv_usec / 1000000.0) - (firstPacketTime.tv_sec + firstPacketTime.tv_usec / 1000000.0);

    // Calcola il tempo dell'ultimo intervallo (può essere meno di 30 secondi)
    finalIntervalTime = (lastPacketTime.tv_sec + lastPacketTime.tv_usec / 1000000.0) - (intervalStartTime.tv_sec + intervalStartTime.tv_usec / 1000000.0);

    if (totalCaptureTime == 0) {
        printf("Error: total capture time is 0, unable to calculate.\n");
        return;
    }

    // Se l'ultimo intervallo è inferiore a 30 secondi, esegui comunque il check DDoS
    if (finalIntervalTime > 0) {

        if(mode!=2){
            printf("\nFinal interval duration: %.2f seconds\n", finalIntervalTime);
            check_for_ddos(intervalPkts, intervalBytes, finalIntervalTime);
        }else{
            if((double)intervalPkts / finalIntervalTime>PACKET_THRESHOLD){
                PACKET_THRESHOLD=(double)intervalPkts / finalIntervalTime;
            }
            //printf("CONTROLLO,Packets in interval: %.1f, soglia:  %llu\n", (double)intervalPkts / finalIntervalTime, PACKET_THRESHOLD );
            //printf("Soglia=%llu",PACKET_THRESHOLD );

        }
    }
    
    if(mode!=2){
        // Stampa delle statistiche finali
        printf("\nTotal capture time: %.2f seconds\n", totalCaptureTime);
        printf("Total Packets: %llu, Total Bytes: %llu\n", numPkts, numBytes);
        printf("Overall Packets/sec: %.1f, Overall Bytes/sec: %.2f KB/sec\n",(double)numPkts / totalCaptureTime, (double)numBytes / (totalCaptureTime * 1000));
    }
    if(mode!=2)print_rrd();
}


//funzione che resetta i campi
void reset_counters() {
    numPkts = 0;
    numBytes = 0;
    intervalPkts = 0;
    intervalBytes = 0;
    memset(&firstPacketTime, 0, sizeof(struct timeval));
    memset(&lastPacketTime, 0, sizeof(struct timeval));
    memset(&intervalStartTime, 0, sizeof(struct timeval));
}


//funzione per stampare la lista di file di tipo ".pcap" all'interno del file
void list_files_and_select(char *selected_file) {
    DIR *dir;
    struct dirent *entry;
    int file_index = 1;
    int selected_index = 0;
    char files[100][256];
    int file_count = 0;
    struct stat file_stat;
    char full_path[512];

    // Apri la directory
    dir = opendir("./");
    if (dir == NULL) {
        printf("Errore nell'aprire la directory.\n");
        exit(EXIT_FAILURE);
    }

    // Elenca tutti i file .pcap nella directory
    printf("Elenco dei file disponibili con estensione .pcap:\n");
    while ((entry = readdir(dir)) != NULL) {
        // Costruisci il percorso completo del file
        snprintf(full_path, sizeof(full_path), "%s/%s", "./", entry->d_name);

        // Verifica che sia un file regolare tramite stat()
        if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            // Controlla se l'estensione del file è ".pcap"
            if (strstr(entry->d_name, ".pcap") != NULL) { 
                printf("\t%d: %s\n", file_index, entry->d_name);
                strcpy(files[file_count], entry->d_name); // Salva il nome del file
                file_index++;
                file_count++;
            }
        }
    }

    closedir(dir);

    if (file_count == 0) {
        printf("Nessun file trovato nella directory.\n");
        exit(EXIT_FAILURE);
    }

    // Chiedi all'utente di selezionare un file
    printf("Inserisci il numero corrispondente al file da analizzare: ");
    scanf("%d", &selected_index);

    // Verifica se l'indice è valido
    if (selected_index < 1 || selected_index > file_count) {
        printf("Indice non valido.\n");
        exit(EXIT_FAILURE);
    }

    // Copia il nome del file selezionato
    strcpy(selected_file, files[selected_index - 1]);
}




void printfirsttool(){

    printf("   -----------------------------------------------------------------------------------------------------------------------------------------------\n");
    
    printf("  |      __      __   _                      _        _              _   _             _              _      _            _   _                   |\n");
    printf("  |      \\ \\    / /  | |                    | |      (_)            | | | |           | |            | |    | |          | | (_)                  |\n");
    printf("  |       \\ \\  / /__ | |_   _ _ __ ___   ___| |_ _ __ _  ___    __ _| |_| |_ __ _  ___| | _____    __| | ___| |_ ___  ___| |_ _  ___  _ __        |\n");
    printf("  |        \\ \\/ / _ \\| | | | | '_ ` _ \\ / _ \\ __| '__| |/ __|  / _` | __| __/ _` |/ __| |/ / __|  / _` |/ _ \\ __/ _ \\/ __| __| |/ _ \\| '_ \\       |\n");
    printf("  |         \\  / (_) | | |_| | | | | | |  __/ |_| |  | | (__  | (_| | |_| || (_| | (__|   <\\__ \\ | (_| |  __/ ||  __/ (__| |_| | (_) | | | |      |\n");
    printf("  |          \\/ \\___/|_|\\__,_|_| |_| |_|\\___|\\__|_|  |_|\\___|  \\__,_|\\__|\\__\\__,_|\\___|_|\\_\\___/  \\__,_|\\___|\\__\\___|\\___|\\__|_|\\___/|_| |_|      |\n");

    printf("  |\t\t\t\tpremi:                                                                                                            |\n");
    printf("  |  \t\t\t\t1: se hai già un file di tipo PCAP pronto da analizzare;                                                          |\n");
    printf("  |  \t\t\t\t2: se vuoi entrare in modalità 'analisi dei limiti'                                                               |\n");
    printf("  |  \t\t\t\t3: se vuoi entrare in modalità ascolto                                                                            |\n");

    printf("   -----------------------------------------------------------------------------------------------------------------------------------------------\n");

}


// Funzione per verificare e trasferire il file tramite SCP
int fetch_pcap_file() {
    char scp_command[512];
    snprintf(scp_command, sizeof(scp_command), "scp -i %s %s@%s:%s %s", SSH_KEY_PATH, MIKROTIK_USER, MIKROTIK_IP, REMOTE_FILE, LOCAL_FILE);
    return system(scp_command);  // Esegui il comando SCP
}

// Funzione per cancellare il file remoto su MikroTik
int remove_remote_file() {
    char ssh_command[512];
    snprintf(ssh_command, sizeof(ssh_command), "ssh -i %s %s@%s 'rm %s'", SSH_KEY_PATH, MIKROTIK_USER, MIKROTIK_IP, REMOTE_FILE);
    return system(ssh_command);  // Esegui il comando SSH per rimuovere il file
}

// Funzione per riavviare lo sniffer su MikroTik
int start_sniffer() {
    char ssh_command[512];
    snprintf(ssh_command, sizeof(ssh_command), "ssh -i %s %s@%s '/tool sniffer start;'", SSH_KEY_PATH, MIKROTIK_USER, MIKROTIK_IP);
    return system(ssh_command);  // Esegui il comando SSH per avviare lo sniffer
}

// Funzione per stoppare lo sniffer su MikroTik
int stop_sniffer(){
    char ssh_command[512];
    snprintf(ssh_command, sizeof(ssh_command), "ssh -i %s %s@%s '/tool sniffer stop;'", SSH_KEY_PATH, MIKROTIK_USER, MIKROTIK_IP);
    return system(ssh_command);  // Esegui il comando SSH per stoppare lo sniffer
}

// Funzione per configurare il tool di sniffing su MikroTik
int configuration(){
    char ssh_command[512];
    snprintf(ssh_command, sizeof(ssh_command), "ssh -i %s %s@%s '/tool/sniffer/set file-name=%s file-limit=10k memory-scroll=yes filter-ip-protocol=udp'", SSH_KEY_PATH, MIKROTIK_USER, MIKROTIK_IP,FILE_TO_CHECK);
    return system(ssh_command);  // Esegui il comando SSH per settare le configurazioni del file
}


// Funzione per controllare e gestire i file PCAP
int check_and_process_pcap() {
    int count = 0;
    int max_iterations = (mode == 2) ? 2 : -1;  // Se in modalità 2, esegui solo 6 iterazioni
    if (configuration() != 0) {
        printf("Configurazione non avvenuta con successo\n");
        return -1;
    }
    printf("File configurato correttamente...\n");

    while (mode == 3 || (mode == 2 && count < max_iterations)) {
        count++;

        // Avvia lo sniffer su MikroTik
        if (start_sniffer() == 0) {
            if(mode!=2)printf("Sniffer avviato con successo!\n");
        }

        if (mode!=2) {
            printf("Ho avviato la cattura dei pacchetti numero: %d e attendo %d secondi per l'analisi numero %d\n", count, SLEEP_INTERVAL, count + 1);
        } else {
            printf("Ho avviato l'iterazione numero: %d di %d\n", count, max_iterations);
        }
        sleep(SLEEP_INTERVAL);

        // Tenta di recuperare il file dal firewall MikroTik
        if(mode!=2)printf("Tentativo di scaricare il file dal firewall...\n");
        if (stop_sniffer() == 0) {
            if (fetch_pcap_file() == 0) {
                if(mode!=2)printf("File scaricato con successo!\n");

                // Reset delle variabili per una nuova analisi
                reset_counters();

                // Apri il file PCAP appena scaricato
                char errbuf[PCAP_ERRBUF_SIZE];
                if ((pd = pcap_open_offline(FILE_TO_CHECK, errbuf)) == NULL) {
                    printf("Errore nell'aprire il file PCAP: %s\n", errbuf);
                    return -1;
                }

                // Avvia l'analisi
                if(mode!=2)printf("Analisi in corso...\n");
                pcap_loop(pd, -1, dummyProcessPacket, NULL);

                // Stampa le statistiche finali solo in modalità 3
                print_final_stats();

                // Chiudi il file PCAP
                pcap_close(pd);

                // Elimina il file locale
                remove(LOCAL_FILE);

                // Elimina il file remoto su MikroTik
                if (remove_remote_file() == 0) {
                    printf("File remoto eliminato con successo!\n");
                }
                printf("Attesa di %d secondi prima del prossimo controllo...\n", SLEEP_INTERVAL);
            } else {
                printf("File non trovato o errore nel download. Attendo %d secondi...\n", SLEEP_INTERVAL);
            }
        } else {
            printf("Sniffing non stoppato correttamente\n");
            return -1;
        }

        // Esci dal ciclo dopo 6 iterazioni in modalità 2
        if (mode == 2 && count == max_iterations) {
            printf("Raggiunto il numero massimo di %d iterazioni, uscita dal ciclo\n",max_iterations);
            printf("\t\t\t L'analisi del traffico ha portato ad una soglia della rete a %llu Packets/sec, continuo l'analisi con tale soglia+100\n",PACKET_THRESHOLD);
            break;
        }
    }
    return 0;
}

void handle_sigint(int sig) {
    printf("\nHo catturato l'interruzione e ho interrotto la cattura\n");
    stop_sniffer();
    exit(0);
}

int main(int argc, char* argv[]) {
    char *device = (char *)malloc(256 * sizeof(char));

    char errbuf[PCAP_ERRBUF_SIZE];
    struct stat s;

    int action;
    printfirsttool();

    scanf("%d", &action);
    signal(SIGINT, handle_sigint);
    switch(action) {
        case 1:
            mode=1;
            list_files_and_select(device);
            break;
        case 2:
            mode=2;
            PACKET_THRESHOLD=1;
            printf("modalità analisi dei limiti avviata\n");
            printf("Cercando di connettermi al firewall...\n");
            if(check_and_process_pcap()== -1 ){
                return 0;
            }
        case 3:
            mode=3;
            PACKET_THRESHOLD+=100;
            printf("Modalità ascolto avviata con soglia %llu Packets/sec. Controllo ogni %d secondi se esiste '%s'.\n",PACKET_THRESHOLD,SLEEP_INTERVAL,FILE_TO_CHECK);
            check_and_process_pcap();
            break;
        default:
            printf("Numero errato\n");
            return 0;
    }
    
    printf("Modalità analisi avviata con soglia %llu Packets/sec. Controllo ogni %d secondi se esiste '%s'.\n",PACKET_THRESHOLD,SLEEP_INTERVAL,FILE_TO_CHECK);
    bool choise=true;
    while(choise){
        if (stat(device, &s) == 0) {
            if ((pd = pcap_open_offline(device, errbuf)) == NULL) {
                printf("pcap_open_offline: %s\n", errbuf);
                return -1;
            }
        } else {
            printf("Error: file %s not found.\n", device);
            return -1;
        }

        printf("\n\n\n\tAnalyzing file: %s\n", device);

        pcap_loop(pd, -1, dummyProcessPacket, NULL);

        print_final_stats();

        pcap_close(pd);
        char var;
        printf("\n\t\t\t\tVuoi analizzare un nuovo file?\n\t\t\t\ty:yes oppure n:no ");
        scanf(" %c", &var);
        printf("\n");
        if (var == 'y') {
            choise = true;
            list_files_and_select(device);
            reset_counters();
            reset_rrd();
        } else {
            choise = false;
        }
    }
    return 0;
}
