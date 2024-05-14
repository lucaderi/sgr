/*
 * Progetto corso Gestione di Rete - Anno Accademico 23/24
 * AirWatch - Made by Giovanni D'Alessandro
 * 
*/

/* Librerie */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <stdint.h>

#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>

#include <pcap.h>
// Libreria utilizzata per l'header RadioTap
#include "Radiotap_LIB/radiotap.h"  

// Libreria utilizzata per implementare le strutture dati necessarie
#include "MyHash_Lib/myhash_lib.h"  

/* Macro e definizioni */
#define MAX_BYTE_2_CAPTURE 2048
#define FREQUENCY_2_4_MIN 2412
#define FREQUENCY_2_4_MAX 2484
#define FREQUENCY_5_MIN 5180
#define FREQUENCY_5_MAX 5825
#define SSID_MAX_LENGTH 32

#define DATA_TYPE 0x08
#define BEACON_TYPE 0x80

/* Strutture dati */
typedef unsigned char u_char;

/* Prototipi di funzioni */
static void sig_gestore(int signum);
void printhelp();
int set_monitor_mode(char *device);
int set_managed_mode(char *device);

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void beacon_handler(const struct pcap_pkthdr *header, const u_char *packet);
void data_handler(const struct pcap_pkthdr *header, const u_char *packet);
void write_mac_address(char *mac_address, const u_char *packet);

void print_overview(HashTable* hashTable);
int count_device(HashDeviceTable* hashDeviceTable);
const char* qualita_segnale(int rssi);

/* Variabili globali */
char *device;
HashTable* hashTable;
static int packet_count;
int verbose;
int offline;

int main(int argc, char *argv[]){
    /* Variabili locali */
    u_char character;
    int ret_val;
    struct sigaction sig_handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "(wlan type mgt subtype beacon) or (wlan type data)";
    bpf_u_int32 net, mask;
    struct stat s;

    /* Inizializzazione delle variabili globali */
    device = NULL;
    hashTable = (HashTable*)malloc(sizeof(HashTable));
    if(hashTable == NULL){
        fprintf(stderr, "Errore. Impossibile allocare memoria.\n");
        exit(EXIT_FAILURE);
    }
    packet_count = 0;
    offline = 0;

    /* Inizializzo il gestore dei segnali */
    sig_handler.sa_handler = sig_gestore;
    if((sigaction(SIGINT, &sig_handler, NULL)) == -1){
        perror("Error in signal handler setting: ");
        exit(EXIT_FAILURE);
    }

    /* Controllo se il programma è stato avviato in modalità super user */
    if(geteuid() != 0){
        fprintf(stderr, "Please, run as superuser.\n");
        exit(EXIT_FAILURE);
    }

    /* Controllo le varie impostazioni */
    while((character = getopt(argc, argv, "hi:v:")) != -1){
        if(character == 255) break;
        switch(character){
            // Help
            case 'h':
                printhelp();
                exit(EXIT_SUCCESS);
                break;
            // Interfaccia
            case 'i':
                device = strdup(optarg);
                break;
            // Verbose
            case 'v':
                verbose = atoi(optarg);
                break;
        }
    }

    // Controllo l'interfaccia
    if(device == NULL){
        fprintf(stderr, "Error: you need to enter a wifi network interface. (-i).\n");
        printhelp();
        exit(EXIT_FAILURE);
    }

    // Controllo se è stato scelto se stampare i mac address dei device o no
    if(verbose != 1 && verbose != 2){
        fprintf(stderr, "Error: you have to choose whether to print the mac addresses of the devices or not.\n");
        exit(EXIT_FAILURE);
    }

    // Controllo se la device è un file (quindi offline capture) oppure è una vera interfaccia di rete
    if(stat(device, &s) == 0){
        // La device è un file
        if((handle = pcap_open_offline(device, errbuf)) == NULL){
            fprintf(stderr, "Errore pcap_open_live: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        // Setto un flag per poter eseguire la cattura offline dei pacchetti
        offline = 1;
    } else { 
        // Apro l'interfaccia in monitor mode
        if(set_monitor_mode(device) != 0){
            fprintf(stderr, "Error activating Monitor Mode.\n");
            exit(EXIT_FAILURE);
        } else {
            fprintf(stdout, "- Monitor Mode successfully enabled.\n");
        }

        fprintf(stdout,"- Premi CTRL+C per fermare la cattura dei pacchetti.\n");

        // Setto a 0 la zona di memoria di errbuf
        memset(errbuf, 0, PCAP_ERRBUF_SIZE);

        // Apro la sessione di cattura sull'interfaccia di rete passata dall'utente
        handle = pcap_open_live(device, MAX_BYTE_2_CAPTURE, 1, 512, errbuf);
        if(handle == NULL){
            fprintf(stderr, "Errore pcap_open_live: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    // Compilo il filtro (Solo pacchetti BEACON e pacchetti DATI)
    if(pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "Error the filter could not be filled: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Applico il filtro
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error the filter could not be set: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Analizzo i pacchetti
    pcap_loop(handle, -1, process_packet, NULL);

    // Chiudo l'interfaccia di rete
    pcap_close(handle);

    // In caso di apertura offline, stampo l'overview della rete senza dover aspettare CTRL+C
    if(offline){
        // Stampo l'overview
        print_overview(hashTable);
        // Libero la memoria allocata dinamicamente per le tabelle hash
        deallocate_hash_table(hashTable);

        exit(EXIT_SUCCESS);
    }
    
    return 0;
}

/* sig_gestore si occupa di:
    - catturare il segnale Ctrl+C per stoppare la cattura dei pacchetti;
    - riabilitare la managed mode e portare on la scheda di rete (set_managed_mode);
    - stampa l'overview della rete (print_overview);
    - chiama la funzione deallocate_hash_table presente nel file myhash_lib.c per deallocare la struttura dati
    - termina l'esecuzione
*/
static void sig_gestore(int signum){
    fprintf(stdout, "- Stopping packet capture...\n");

    // Riabilito la managed mode e porto ON la scheda di rete
    if(set_managed_mode(device) != 0){
        fprintf(stderr, "Error activating Managed Mode.\n");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stdout, "- Managed mode successfully enabled.\n");
    }

    // Stampo un resoconto della rete
    print_overview(hashTable);

    // Libero la memoria allocata dalla struttura dati
    deallocate_hash_table(hashTable);

    // Termino con successo l'esecuzione
    exit(EXIT_SUCCESS);
}

/* printhelp: funzione utilizzata per stampare in stdout una guida sul programma. */
void printhelp(){
    /* variabili locali */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *device_avaible;

    printf("##################################################################################\n");
    printf("                            AIRWATCH v1 - Network Overview                        \n");
    printf("##################################################################################\n");
    printf("Usage: sudo ./wifi_scan [-h] [-i <device|path>] [-v <verbose>]\n");
    printf(" -h                      [Print Help]\n");
    printf(" -i <wifi device|path>   [WiFi device name or file path]\n");
    printf(" -v <verbose>            [Verbose: 1 (Number of device) 2 (Print the MAC Address)]\n");
    printf("\n");
    printf("Avaible device (-i):\n");

    // Genera la lista delle device disponibili
    if(pcap_findalldevs(&device_avaible, errbuf) == 0){
        while(device_avaible->next != NULL){ // Scorre la lista
            char *descrizione = device_avaible->description;
            // Controllo se l'interfaccia di rete è  un interfaccia wireless
            if(device_avaible->flags & PCAP_IF_WIRELESS){
                if(descrizione != NULL){
                    printf(" - %s [%s]\n", device_avaible->name, descrizione);
                } else {
                    printf(" - %s\n", device_avaible->name);
                }
            }
            device_avaible = device_avaible->next;
        }
    } else {
        perror("Device error: ");
        exit(EXIT_FAILURE);
    }

    // Libero la memoria allocata dalla pcap_findalldevs
    pcap_freealldevs(device_avaible);
}

/* set_monitor_mode si occupa di:
    - usare airmon-ng per killare tutti i processi che stanno utilizzando la scheda di rete usata passata come parametro;
    - spegne l'interfaccia di rete;
    - abilita la monitor mode;
    - accende l'interfaccia di rete;
*/
int set_monitor_mode(char *device){
    int ret_val;
    char command[100];
    // Kill the process that use NetworkManager
    fprintf(stdout, "- Killing processes that use the network card...\n");
    sprintf(command, "airmon-ng check kill > /dev/null 2>&1");
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Error aritmon-ng.\n");
        return -1;
    }

    // Turn off the Network Interface
    fprintf(stdout, "- Turning OFF the network interface...\n");
    sprintf(command, "ip link set %s down", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn off the device.\n");
        return -1;
    }

    // Turn on the Monitor Mode
    fprintf(stdout, "- Turning ON monitor mode...\n");
    sprintf(command, "iw %s set monitor none", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn on the monitor mode.\n");
        return -1;
    }

    // Turn off the Network Interface
    fprintf(stdout, "- Turning ON the network interface...\n");
    sprintf(command, "ip link set %s up", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn on the device.\n");
        return -1;
    }
    return 0;
}

/* set_managed_mode si occupa di:
    - spegne l'interfaccia di rete;
    - abilita la managed mode;
    - accende l'interfaccia di rete;
    - fa ripartire il NetworkManager;
*/
int set_managed_mode(char *device){
    int ret_val;
    char command[100];

    // Turn off the Network Interface
    fprintf(stdout, "- Turning OFF the network interface...\n");
    sprintf(command, "ip link set %s down", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn off the device.\n");
        return -1;
    }

    // Turn on the Monitor Mode
    fprintf(stdout, "- Turning ON managed mode...\n");
    sprintf(command, "iw %s set type managed", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn on the managed mode.\n");
        return -1;
    }

    // Turn off the Network Interface
    fprintf(stdout, "- Turning ON the network interface..\n");
    sprintf(command, "ip link set %s up", device);
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn on the device.\n");
        return -1;
    }

    // Turn on the Network Service
    fprintf(stdout, "- Turning On NetworkManager...\n");
    sprintf(command, "service NetworkManager start");
    if((ret_val = system(command)) == -1){
        fprintf(stderr, "Unable to turn on NetworkManager.\n");
        return -1;
    }

    return 0;
}

/* process_packet si occupa di controllare il frame type del pacchetto, per chiamare due funzioni:
    - (beacon_handler) gestisce i pacchetti beacon;
    - (data_handler) gestisce i pacchetti dati;
*/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Controllo il Frame Type per sapere se è un pacchetto Beacon o Data
    u_char frame_type = packet[36];
    switch(frame_type){
        case BEACON_TYPE:
            beacon_handler(header, packet);
            break;
        case DATA_TYPE:
            data_handler(header, packet);
            break;
    }
}
/* beacon_handler si occupa di ispezzionare il pacchetto beacon ricevuto per ricavare le seguenti informazioni:
    - SSID e MAC Address dell'Access Point;
    - Frequenza;
    - Canale;
    - Potenza del segnale;
    - Antenna;
    - Trasmissione dei dati.
    Chiama la funzione (insert_beacon_frame) per popolare la tabella hash.
*/
void beacon_handler(const struct pcap_pkthdr *header, const u_char *packet) {
    // Inizializzo la struttura dati necessaria per salvare i dati relativi al WiFi
    WiFiDevice wifi_device;

    // Ottengo il timestamp dal pacchetto
    struct timeval timestamp = header->ts;

    // Converto il timestamp
    char timestamp_str[64];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", localtime(&(timestamp.tv_sec)));

    // Estraggo l'header Radiotap
    struct ieee80211_radiotap_header *radiotap_header = (struct ieee80211_radiotap_header *) packet;

    // Trovo la lunghezza dell'header Radiotap
    int radiotap_length = radiotap_header->it_len;

    /* Inizio l'estrazione dei dati dal pacchetto */

    // Calcolola frequenza e il canale
    int frequency = (packet[27] << 8) | packet[26];
    int channel = -1;
    if(frequency >= FREQUENCY_2_4_MIN && frequency <= FREQUENCY_2_4_MAX){
        // Calcolo del canale nella banda dei 2.4 GHz
        channel = (frequency - FREQUENCY_2_4_MIN) / 5 + 1;
    } else if(frequency >= FREQUENCY_5_MIN && frequency <= FREQUENCY_5_MAX){
        // Calcolo del canale nella banda dei 5 ghz
        channel = (frequency - 5000) / 5;
    }

    // Estraggo il segnale dall'antenna (RSSI) e il numero dell'antenna
    int antenna_signal = (int) packet[30];
    if(antenna_signal > 127){
        antenna_signal = antenna_signal - 256;
    }
    int antenna_number = (int) packet[35];

    // Estraggo il data rate
    float data_rate = packet[25] * 0.5;

    // Calcolo l'inizio della zona dati del pacchetto
    const u_char *ieee80211_data = packet + radiotap_length;

    // Estraggo gli indirizzi MAC del trasmettitore e del destinatario
    char mac_address_rx[18], mac_address_tx[18];
    // Utilizzo una funzione ausiliaria per salvare il MAC Address formattato all'interno della variabile
    write_mac_address(mac_address_rx, ieee80211_data + 4);
    write_mac_address(mac_address_tx, ieee80211_data + 10);

    // Estraggo l'SSID
    char ssid[SSID_MAX_LENGTH + 1];
    int ssid_length = ieee80211_data[37];
    if (ssid_length > 0 && ssid_length <= SSID_MAX_LENGTH) {
        strncpy(ssid, (char *) &ieee80211_data[38], ssid_length);
        ssid[ssid_length] = '\0';
    } else {
        // Se il nome della rete non è valido, viene assegnato "Unknown"
        strncpy(ssid, "Unknown", SSID_MAX_LENGTH);
        ssid[SSID_MAX_LENGTH] = '\0';
    }

    // Ulteriore controllo per garantire la correttezza del nome SSID
    if (ssid_length != strlen(ssid)) {
        strcpy(ssid, "Unknown");
        return;
    }

    // Variabile globale utilizzata per tenere traccia del numero totale dei pacchetti che sono stati analizzati
    packet_count++;

    // Salvo i dati ottenuti dall'ispezione del pacchetto nella struttura dati
    strcpy(wifi_device.mac_AccessPoint, mac_address_tx);
    strcpy(wifi_device.ssid, ssid);
    wifi_device.frequency = frequency;
    wifi_device.channel = channel;
    wifi_device.signal_strength = antenna_signal;
    wifi_device.antenna_number = antenna_number;
    wifi_device.data_rate = data_rate;

    // Inserisco i dati della struct appena popolata nella tabella hash
    insert_beacon_frame(hashTable, &wifi_device);

    // Stampo in stdout il pacchetto
    printf("%d. [Beacon Frame] [%s.%06d] | Freq: %d MHz (Ch: %d) | Signal: %d dBm | Ant: %d | Rate: %.1f Mb/s\n",
          packet_count,
          timestamp_str, (int)timestamp.tv_usec,
          frequency, channel,
          antenna_signal,
          antenna_number, 
          data_rate);
    printf("- SSID: %s | [Tx: %s]->[Rx: %s]\n", ssid, mac_address_tx, mac_address_rx);
}

/* data_handler si occupa di ispezzionare il pacchetto beacon ricevuto per ricavare le seguenti informazioni principali:
    - MAC Address dell'Access Point;
    - MAC Address del dispositivo che ha inviato il pacchetto
    Utilizza il MAC Address dell'Access Point come chiave per creare una tabella hash di dispositivi che trasmettono dati in una certa rete.
    
    NB: dal pacchetto ricava anche le informazioni ottenute dal pacchetto Beacon, ma vengono usate solo per la stampa in stdout

    Chiama la funzione (insert_data_frame) per popolare la tabella hash.
*/
void data_handler(const struct pcap_pkthdr *header, const u_char *packet){
    // Varaiabile globale utilizzata per incrementare il numero dei pacchetti visti
    packet_count++;

    // Ottengo il timestamp dal pacchetto
    struct timeval timestamp = header->ts;

    // Converto il timestamp
    char timestamp_str[64];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", localtime(&(timestamp.tv_sec)));

    // Estraggo l'header Radiotap
    struct ieee80211_radiotap_header *radiotap_header = (struct ieee80211_radiotap_header *) packet;

    // Trovo la lunghezza dell'header Radiotap
    int radiotap_length = radiotap_header->it_len;

    /* Inizio l'estrazione dei dati dal pacchetto */

    // Calcolola frequenza e il canale
    int frequency = (packet[27] << 8) | packet[26];
    int channel = -1;
    if(frequency >= FREQUENCY_2_4_MIN && frequency <= FREQUENCY_2_4_MAX){
        channel = (frequency - FREQUENCY_2_4_MIN) / 5 + 1; // Calcolo del canale nella banda dei 2.4 GHz
    } else if(frequency >= FREQUENCY_5_MIN && frequency <= FREQUENCY_5_MAX){
        channel = (frequency - 5000) / 5; // Calcolo del canale nella banda dei 5 ghz
    }

    // Estraggo il segnale dall'antenna (RSSI) e il numero dell'antenna
    int antenna_signal = (int) packet[30];
    if(antenna_signal > 127){
        antenna_signal = antenna_signal - 256;
    }
    int antenna_number = (int) packet[35];

    // Estraggo il data rate
    float data_rate = packet[25] * 0.5;

    // Calcolo l'inizio della zona dati del pacchetto
    const u_char *ieee80211_data = packet + radiotap_length;

    // Estraggo gli indirizzi MAC del trasmettitore e del destinatario
    char mac_address_rx[18], mac_address_tx[18], mac_address_source[18];
    write_mac_address(mac_address_rx, ieee80211_data + 4);
    write_mac_address(mac_address_tx, ieee80211_data + 10);
    write_mac_address(mac_address_source, ieee80211_data + 16);

    printf("%d. [Data Frame] [%s.%06d] | Freq: %d MHz (Ch: %d) | Signal: %d dBm | Ant: %d | Rate: %.1f Mb/s\n",
          packet_count,
          timestamp_str, (int)timestamp.tv_usec,
          frequency, channel,
          antenna_signal,
          antenna_number, 
          data_rate);

    printf("- [Trasmitter Address: %s] [Source Address: %s] -> [Receiver address: %s]\n", 
            mac_address_tx,
            mac_address_source,
            mac_address_rx);

    insert_data_frame(hashTable, mac_address_tx, mac_address_source);
}

/* write_mac_address: funzione ausiliaria per stampare il MAC Address formattato. */
void write_mac_address(char *mac_address, const u_char *packet){
    int index = 0;
    for(int i = 0; i < 6; i++){
        index += sprintf(mac_address + index, "%02x", packet[i]);
        if(i < 5){
            mac_address[index++] = ':'; // Assegna il carattere ':' direttamente all'indice corrente e poi incrementa index
        }
    }
    mac_address[index] = '\0'; // Assicurati che la stringa sia terminata correttamente
}

/* print_overview si occupa di stampare l'ultimo pacchetto beacon arrivato per ogni rete, con i MAC Address dei dispositivi rilevati. */
void print_overview(HashTable* hashTable){
    int flag = 0;
    printf("\n###################################################################\n");
    printf("                   AIRWATCH v1 - Network Overview        \n");
    printf("###################################################################\n\n");
    for(int i = 0; i < TABLE_SIZE; i++){
        if(hashTable->table[i] != NULL){
            HashElement* element = hashTable->table[i];
            while(element != NULL){
                WiFiDevice wifi_dev = element->value;
                // Controllo se è una rete valida
                if(strcmp(wifi_dev.ssid, "Unknown") != 0){
                    // È una rete valida, quindi abbiamo dei dati verificati
                    printf("SSID: %s [%s] - Dettagli della rete\n", wifi_dev.ssid, wifi_dev.mac_AccessPoint);
                    printf("-------------------------------------------------------------------\n");
                    printf("    Frequency:      %d MHz\n", wifi_dev.frequency);
                    printf("    Channel:        %d\n", wifi_dev.channel);
                    printf("    Antenna:        %d\n", wifi_dev.antenna_number);
                    printf("    RSSI:           %d dBm [%s]\n", wifi_dev.signal_strength, qualita_segnale(wifi_dev.signal_strength));
                    printf("    Data Rate:      %.1f Mb/s\n", wifi_dev.data_rate);
                } else {
                    // Se non è una rete valida, stampo solo l'ssid e il MAC Associato
                    printf("SSID: %s [%s] - Dettagli della rete\n", wifi_dev.ssid, wifi_dev.mac_AccessPoint);
                    printf("-------------------------------------------------------------------");
                }
                printf("\n  Pacchetti dati rilevati:\n");
                HashDeviceTable *hashDeviceTable = &(element->devices);
                if (verbose - 1) {
                    for (int i = 0; i < TABLE_SIZE; i++) {
                        HashDeviceElement *current = hashDeviceTable->table[i];
                        while (current != NULL) {
                            printf("    - MAC Address: [%s] | Pacchetti inviati [%d]\n", current->key, current->device.packet_sent);
                            current = current->next;
                            flag = 1;
                        }
                    }
                    if(!flag){
                        printf("    - Non sono stati rilevati MAC Address che inviavano pacchetti dati.\n");
                        flag = 0;
                    }
                } else {
                    printf(" - Ci sono [%d] dispositivi che trasmettono pacchetti dati.\n", count_device(hashDeviceTable));
                }

                element = element->next;
                printf("===================================================================\n\n");
            }
        }
    }
}

/* count device si occupa di stampare il numero dei device che hanno trasmesso pacchetti dati per una data rete wifi. */
int count_device(HashDeviceTable *hashDeviceTable){
    int num_device = 0;
    
    for(int i = 0; i < TABLE_SIZE; i++){
        HashDeviceElement *current = hashDeviceTable->table[i];
        while(current != NULL){
            num_device++;
            current = current->next;
        }
    }

    return num_device;
}

/* qualita_segnale in base al segnale rssi passato come parametro ci dice la forza del segnale*/
const char* qualita_segnale(int rssi){
    if(rssi > -50){
        return "Eccellente";
    } else if(rssi > -60){
        return "Buona";
    } else if(rssi > -70){
        return "Accettabile";
    } else if(rssi > -80){
        return "Debole";
    } else{
        return "Scarsa";
    }
}