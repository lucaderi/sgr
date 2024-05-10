#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myhash_lib.h"

/* hashFunction: funzione di hash, restituisce l'indice basato sulla chiave*/
unsigned int hashFunction(char* key){
    unsigned int hash = 0;
    while(*key){
        hash = (hash << 5) + *key++;
    }
    return hash % TABLE_SIZE;
}

/* initHashTable: inizializza la tabella hash */
void initHashTable(HashTable* hashTable){
    for(int i = 0; i < TABLE_SIZE; i++){
        hashTable->table[i] = NULL;
    }
}

/* initDeviceTable: inizializza la tabella degli indirizzi MAC associati */
void initDeviceTable(HashDeviceTable* hashDevice){
    for(int i = 0; i < TABLE_SIZE; i++){
        hashDevice->table[i] = NULL;
    }
}

/* insert_beacon_frame: funzione che inserisce un elemento beacon hash nella tabella */
void insert_beacon_frame(HashTable* hashTable, WiFiDevice* value) {
    unsigned int index = hashFunction(value->mac_AccessPoint);

    // Cerco se l'elemento esiste già con la stessa chiave
    HashElement* current = hashTable->table[index];
    while(current != NULL){
        if(strcmp(current->key, value->mac_AccessPoint) == 0){
            // Se l'elemento esiste già sostituisce l'elemento con quello nuovo
            current->value = *value;
            return;
        }
        current = current->next;
    }

    // Alloco memoria per il nuovo elemento
    HashElement* newElement = (HashElement*)malloc(sizeof(HashElement));
    if(newElement == NULL){
        fprintf(stderr, "Errore: Impossibile allocare memoria.\n");
        exit(EXIT_FAILURE);
    }

    // Copio la chiave e il valore nell'elemento
    strcpy(newElement->key, value->mac_AccessPoint);
    newElement->value = *value;
    newElement->next = NULL;
    initDeviceTable(&(newElement->devices));

    // Se non ci sono collisioni, aggiungi direttamente all'array
    if(hashTable->table[index] == NULL){
        hashTable->table[index] = newElement;
    } else {
        // Se c'è una collisione, aggiungi alla fine della lista concatenata
        HashElement* current = hashTable->table[index];
        while(current->next != NULL){
            current = current->next;
        }
        // Aggiungi il nuovo elemento alla fine della lista concatenata
        current->next = newElement;
        newElement->next = NULL;  // Imposta il next del nuovo elemento a NULL
    }
}

/* insert_data_frame: funzione che inserisce un elemento data hash nella tabella */
void insert_data_frame(HashTable* hashTable, char *key, char* mac_source) {
    unsigned int index = hashFunction(key);
    
    // Cerca se l'elemento esiste già
    HashElement* current = hashTable->table[index];
    while(current != NULL){
        if(strcmp(current->key, key) == 0) {
            // L'elemento esiste già, quindi aggiungo il mac address alla tabella dei dispositivi
            mac_address_insert(&(current->devices), mac_source);
            return;
        }
        current = current->next;
    }

    // Se l'elemento non esiste, crea un nuovo elemento
    HashElement* newElement = (HashElement*)malloc(sizeof(HashElement));
    if(newElement == NULL) {
        fprintf(stderr, "Errore: Impossibile allocare memoria.\n");
        exit(EXIT_FAILURE);
    }
    strcpy(newElement->key, key);


    WiFiDevice* newDevice = (WiFiDevice*)malloc(sizeof(WiFiDevice));
    if(newDevice == NULL){
        fprintf(stderr, "Errore. Impossibile allocare memoria.\n");
        exit(EXIT_FAILURE);
    }
    strcpy(newDevice->ssid,"Unknown");
    strcpy(newDevice->mac_AccessPoint,key);
    newDevice->antenna_number = 0;
    newDevice->channel = 0;
    newDevice->data_rate = 0;
    newDevice->frequency = 0;
    newDevice->signal_strength = 0;

    newElement->value = *newDevice;
    initDeviceTable(&(newElement->devices));
    mac_address_insert(&(newElement->devices), mac_source);
    newElement->next = NULL;
    
    // Aggiungi l'elemento all'array o alla fine della lista concatenata
    if(hashTable->table[index] == NULL){
        hashTable->table[index] = newElement;
    } else {
        // Trova l'ultimo elemento nella lista concatenata
        HashElement* lastElement = hashTable->table[index];
        while(lastElement->next != NULL){
            lastElement = lastElement->next;
        }
        // Aggiungi il nuovo elemento alla fine della lista concatenata
        lastElement->next = newElement;
        newElement->next = NULL;  // Imposta il next del nuovo elemento a NULL
    }

    return;
}

/* mac_address_insert: funzione che inserisce il MAC Address del dispositivo nella tabella hash */
void mac_address_insert(HashDeviceTable *hashDeviceTable, char key[]){
    // Calcolo la key
    unsigned int index = hashFunction(key);
    
    HashDeviceElement* current = hashDeviceTable->table[index];
    while(current != NULL){
        if(strcmp(current->key, key) == 0){
            // Se è già presente il MAC Address della chiave aumento il numero dei pacchetti
            current->device.packet_sent++;
            return;
        }
        current = current->next;
    }

    // Se l'elemento non esiste, creo un nuovo elemento
    HashDeviceElement* deviceElement = (HashDeviceElement*)malloc(sizeof(HashDeviceElement));
    if(deviceElement == NULL){
        fprintf(stderr, "Impossibile allocare memoria.\n");
        exit(EXIT_FAILURE);
    }

    // Inizializzo i campi del nuovo elemento
    strcpy(deviceElement->key, key);
    strcpy(deviceElement->device.mac_address_device, key);
    deviceElement->device.packet_sent = 1;
    deviceElement->next = NULL;

    // Se non ci sono collisioni, aggiungi direttamente all'array
    if(hashDeviceTable->table[index] == NULL){
        hashDeviceTable->table[index] = deviceElement;
    } else {
        // Se c'è una collisione, aggiungi alla fine della lista concatenata
        HashDeviceElement* current = hashDeviceTable->table[index];
        while(current->next != NULL){
            current = current->next;
        }
        // Aggiungi il nuovo elemento alla fine della lista concatenata
        current->next = deviceElement;
        deviceElement->next = NULL;  // Imposta il next del nuovo elemento a NULL
    }
    return;
}

/* deallocate_hash_table: funzione per deallocare la struttura dati */
void deallocate_hash_table(HashTable *hash_table) {
    // Scorrere ogni elemento nella tabella hash
    for (int i = 0; i < TABLE_SIZE; i++) {
        HashElement *current_element = hash_table->table[i];
        while (current_element != NULL) {
            HashElement *temp = current_element;
            current_element = current_element->next;
            
            // Deallocazione della memoria per la tabella hash dei dispositivi WiFi collegati
            HashDeviceElement *current_device_element = temp->devices.table[i];
            while (current_device_element != NULL) {
                HashDeviceElement *temp_device = current_device_element;
                current_device_element = current_device_element->next;
                free(temp_device);
            }
            
            // Deallocazione della memoria per l'elemento corrente nella tabella hash principale
            free(temp);
        }
    }
    // Deallocazione della memoria per la tabella hash principale
    free(hash_table);
}
