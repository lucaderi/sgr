/*
 * myhash_lib: libreria per implementare una tabella hash che contiene i dati delle reti
 */

#define TABLE_SIZE 100

// Struttura per rappresentare un dispositivo che trasmette pacchetti dati
typedef struct {
    char mac_address_device[18];
    int packet_sent;
} MacDevice;

// Struttura per un elemento nella tabella hash dei dispositivi WiFi
typedef struct hash_device {
    char key[18];                   // Key (MAC Address del dispositivo)
    MacDevice device;               // Dispositivo WiFi
    struct hash_device *next;       // Puntatore al prossimo elemento nella lista concatenata
} HashDeviceElement;

// Struttura per la tabella hash dei dispositivi WiFi
typedef struct {
    HashDeviceElement *table[TABLE_SIZE];
} HashDeviceTable;

// Struttura per contenere le informazioni fondamentali della rete WiFi
typedef struct {
    char mac_AccessPoint[18];   // MAC Address Access Point
    char ssid[32];              // SSID della rete WiFi a cui il dispositivo è associato
    int frequency;              // Frequenza (in MHz) su cui il dispositivo trasmette/riceve
    int channel;                // Canale WiFi utilizzato dal dispositivo
    int signal_strength;        // Potenza del segnale ricevuto (RSSI)
    int antenna_number;         // Numero dell'antenna
    float data_rate;            // Trasmissione dei dati
} WiFiDevice;

// Struttura per un elemento nella tabella hash principale
typedef struct hash{
    char key[18];               // Chiave (MAC Address dell'Access Point)
    WiFiDevice value;           // Identifica la struct che contiene le informazioni sulla rete
    HashDeviceTable devices;    // Tabella Hash degli indirizzi MAC che hanno trasmesso pacchetti dati
    struct hash * next;         // Puntatore al prossimo elemento nella lista concatenata
} HashElement;

// Struttura per la tabella hash dei dispositivi WiFi
typedef struct{
    HashElement* table[TABLE_SIZE];
}HashTable;

/* hashFunction: funzione di hash, restituisce l'indice basato sulla chiave */
unsigned int hashFunction(char* key);

/* initHashTable: inizializza la tabella hash */
void initHashTable(HashTable* hashTable);

/* initDeviceTable: inizializza la tabella degli indirizzi MAC associati */
void initDeviceTable(HashDeviceTable* hashDevice);

/* insert_beacon_frame: funzione che inserisce un elemento beacon hash nella tabella */
void insert_beacon_frame(HashTable* hashTable, WiFiDevice* value);

/* insert_data_frame: funzione che inserisce un elemento data hash nella tabella */
void insert_data_frame(HashTable* hashTable, char* key, char* mac_source);

/* mac_address_insert: funzione che inserisce il MAC Address del dispositivo nella tabella hash */
void mac_address_insert(HashDeviceTable* hashDeviceTable, char key[]);

/* deallocate_hash_table: funzione per deallocare la struttura dati */
void deallocate_hash_table(HashTable* hashTable);
