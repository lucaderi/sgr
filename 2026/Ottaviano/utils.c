#include "utils_leaky_bucket.h"
#include "structure.h"
#include <stdbool.h>


/*
    funzione utilizzata nei metodi per stampare le liste
*/
void print_ip32(uint32_t ip){

    // converte i byte dell'ip nell ordine giusto

    uint32_t h = ntohl(ip);
    
    // estrapolo ogni ottetto dall'indirizzo

    uint8_t occ1 = (h >> 24) & 0xff;
    uint8_t occ2 = (h >> 16) & 0xff;
    uint8_t occ3 = (h >> 8) & 0xff;
    uint8_t occ4 = h & 0xff;

    // stampo l'indirizzo

    printf("%d.%d.%d.%d", occ1,occ2,occ3,occ4);
}

void print_bucket(struct Bucket** table){
    for(int i = 0; SIZE > i; i++){
        struct Bucket* b = table[i];
        if(b == 0) continue;

        printf("Bucket[%d] -> ",i);
        print_ip32(b->ip);

        while(b->next != NULL){
            b = b->next;
            printf(" -> ");
            print_ip32(b->ip);
        }
        printf("\n");
    }
}

void print_blacklist(struct Address_node** blacklist){
    for(int i = 0; SIZE > i; i++){
        struct Address_node* b = blacklist[i];
        if(b == 0) continue;

        printf("blacklist[%d] -> ",i);
        print_ip32(b->ip);

        while(b->next != NULL){
            b = b->next;
            printf(" -> ");
            print_ip32(b->ip);
        }
        printf("\n");
    }
}

uint8_t hash(uint32_t ip){

    // converte i byte dell'ip nell ordine giusto

    uint32_t h = ntohl(ip);

    // estrapolo gli ottetti
    
    uint8_t occ1 = (h >> 24) & 0xff;
    uint8_t occ2 = (h >> 16) & 0xff;
    uint8_t occ3 = (h >> 8) & 0xff;
    uint8_t occ4 = h & 0xff;

    // ritorno l'indice relativo all'ip sommando i suoi ottetti
   
    return (occ1 + occ2 + occ3 + occ4) % SIZE;
}

long int calc_rem(struct Bucket* b){
    // calcola quanti invertalli sono passati da quando questo elemento è stato inserito
    return (time(NULL) - b->timestamp) / TTL_IP_IN_BUCKET;
}

void update_blacklist(uint8_t index, struct Address_node** blacklist) {

    /*
        aggiorno la lista nera controllando se ci sono indirizzi
        che sono rimasti per un certo periodo di tempo
    */
    struct Address_node* curr = blacklist[index];
    struct Address_node* prev = NULL;

    while(curr != NULL) {
        if((time(NULL) - curr->timestamp) >= TTL_IP_IN_BLACKLIST) {
            struct Address_node* temp = curr;
            if(prev == NULL) {
                // primo nodo
                blacklist[index] = curr->next;
                curr = curr->next;
            } else {
                prev->next = curr->next;
                curr = curr->next;
            }
            free(temp);
        } else {
            prev = curr;
            curr = curr->next;
        }
    }
}

bool ipInBlacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist){

    // controllo se l'ip è presente nella lista nera

    struct Address_node* curr = blacklist[index];
    while(curr != NULL) {
        if(curr->ip == ip) return true;
        curr = curr->next;
    }
    return false;
}

void check_bucket(struct Bucket** table, struct Address_node** blacklist){

    /*
        controllo se ci sono indirizzi che non inviano più
        pacchetti da un certo periodo di tempo, eliminandoli dalla lista
    
    */

    for(uint8_t i = 0; i < SIZE; i++){

        struct Bucket* prev = NULL;
        struct Bucket* b = table[i];
        
        /*
          AGGIORNO LA LISTA NERA, TOGLIENDO GLI INDIRIZZI CHE 
          SONO STATI ABBASTANZA TEMPO
        */
        update_blacklist(i, blacklist);

        while(b != NULL){

            /*
                rem (remaining) rappresenta numero di 
                intervalli (TTL bucket) trascorsi dall’inserimento
            */

            long int rem = calc_rem(b);

            /*
                level è il livello attuale dell’elemento e lo
                aggiorno sottraendo il tempo trascorso
            */
            if(rem >= b->level) b->level = 0;
            else b->level -= rem;

            // SE IL LIVELLO È ARRIVATO A 0, LO ELIMINO DAL BUCKET
            if(b->level == 0 || ipInBlacklist(b->ip, hash(b->ip), blacklist)){
                struct Bucket* temp = b;

                if(prev == NULL){
                    table[i] = b->next;
                    b = table[i];
                } else {
                    prev->next = b->next;
                    b = b->next;
                }

                struct in_addr addr;
                addr.s_addr = temp->ip;
                printf("Rimosso l'indirizzo %s dal bucket\n", inet_ntoa(addr));
                free(temp);
            } else {
                prev = b;
                b = b->next;
            }
        }
    }
}

void free_buckets(struct Bucket** table){

    /*
        libero la memoria 
    */

    for(int i = 0; SIZE > i; i++){
        struct Bucket* curr = table[i];
        while(curr != NULL){
            struct Bucket* temp = curr;
            curr = curr->next;
            free(temp);
        }
        table[i] = NULL;
    }

}

void free_blacklist(struct Address_node** blacklist){

    /*
        libero la memoria
    */
    
    for(int i = 0; SIZE > i; i++){
        struct Address_node* curr = blacklist[i];
        while(curr != NULL){
            struct Address_node* temp = curr;
            curr = curr->next;
            free(temp);
        }
        blacklist[i] = NULL;
    }

}

void process_packet(unsigned char* user,
    const struct pcap_pkthdr* h,
    const unsigned char* packet, pcap_t* in, pcap_t* out,
    struct Bucket** table, struct Address_node** blacklist,
    char* dev1, char* dev2){

    struct ip_header_* header = (struct ip_header_*)(packet + sizeof(struct eth_header));

    // CONTROLLO SE L'INDIRIZZO È PRESENTE NEL BUCKET

    check_bucket(table, blacklist);
    
    uint32_t ip = header->src_ip;
    struct in_addr addr;
    addr.s_addr = ip;

    // CONTROLLO SE È PRESENTE NLLA LISTA NERA

    if(ipInBlacklist(ip, hash(ip), blacklist)){
       
        printf("Pacchetto scartato di %s\n", inet_ntoa(addr));
        print_bucket(table);
        printf("\n");
        print_blacklist(blacklist);
        return;
    } 

    // PRELEVO L'INDICE DELL'ARRAY IN CUI C'È L'IP CORRENTE
    uint8_t index = hash(ip);

    struct Bucket* b = table[index];
    struct Bucket* prev = NULL;
    bool found = false;

    /*
      CERCO L'IP CORRENTE NEL BUCKET PER:
      1) INCREMENTARE IL LIVELLO
      2) VERIFICARE SE SUPERA LA CAPACITÀ, INSERENDOLO NELLA BLACKLIST
    */

    while(b != NULL){
        if(b->ip == ip){
          // HO TROVATO L'IP NEL BUCKET
            found = true;
            b->timestamp = time(NULL);
            b->level++;

            // SE IL LIVELLO SUPERA LA CAPACITÀ DEL BUCKET, LA INSERISCO NELLA LISTA NERA
            if(b->level > CAPACITY){
                if(!ipInBlacklist(ip, hash(ip), blacklist)){
                    insert_ip_in_blacklist(ip, index, blacklist);
                    printf("Pacchetto da %s inserito nella blacklist\n", inet_ntoa(addr));
                    //fprintf(fp, "[%ld] pacchetto da %s inserito nella blacklist\n", time(NULL), inet_ntoa(addr));
                    //fflush(fp);
                }
            } else {
                // INVIO IL PACCHETTO ALLA SECONDA INTERFACCIA
                if(pcap_sendpacket(out, packet, SIZE_PACKET) != 0){
                    printf("errore nell'invio del pacchetto: %s\n!",pcap_geterr(in));
                } else {
                    printf("[%s] pacchetto inviato all'interfaccia [%s]!\n",
                                dev1, dev2);
                }
            }
            break;
        }
        // COLLISIONE, ESPLORO NELLA LISTA CONCATENATA
        prev = b;
        b = b->next;
    }

    /*
      SE NON HO TROVATO L'IP NEL BUCKET, LO INSERISCO.
    */

    if(!found){
        struct Bucket* newb = malloc(sizeof(struct Bucket));
        if(!newb){
            perror("malloc");
            exit(1);
        }

        newb->ip = ip;
        newb->level = 1;
        newb->timestamp = time(NULL);
        newb->next = NULL;

        if(prev == NULL){
            table[index] = newb;
        } else {
            prev->next = newb;
        }

        if(pcap_sendpacket(out, packet, SIZE_PACKET) != 0){
            printf("errore nell'invio del pacchetto: %s\n!",pcap_geterr(in));
        } else {
            printf("[%s] pacchetto inviato all'interfaccia [%s]!\n",
                        dev1, dev2);
        }
    }

}

void insert_ip_in_blacklist(uint32_t ip, uint8_t index, struct Address_node** blacklist){

    /*
        inserisco l'ip nella lista nera
    */

    struct Address_node* node = (struct Address_node*)malloc(sizeof(struct Address_node));
    
    if(node == NULL){
        perror("malloc address node");
        exit(0);
    }
    
    node->ip = ip;
    node->timestamp = time(NULL);
    node->next = NULL;
    
    if(blacklist[index] == 0){
        blacklist[index] = node;
    } else {
        struct Address_node* temp = blacklist[index];
        while(temp->next != NULL){
            temp = temp->next;
        }
        temp->next = node;
    }

}
