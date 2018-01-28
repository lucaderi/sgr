#include <arpa/inet.h>

/*definisce host ip+porta*/
typedef struct host{
  char *ip;
  uint16_t port;
} host_t;

/*definisce i tipi di dato da salvare*/
typedef struct data{
  uint32_t pkts, bytes;
  time_t fst, lst;
} data_t;

/* tipo elemento della hash table */
typedef struct hashE{
  char * protocol;
  host_t * src, * dst;   /* */
  data_t * data;    /* valore associato a key */
  struct hashE * next;   
} hashElement_t;


/* tipo della tabella hash  (un array di puntatori a hashElement_t) */
typedef struct { 
  int size;    /* ampiezza tabella */
  hashElement_t ** table;
} hashTable_t;

/* FUNZIONI */
/* @description -- crea la labella hash e la inizializza
   @param  sizeH -- numero di elementi nella tabella 
                      (meglio scegliere un numero primo!) 
   @returns -- (puntatore alla nuova hash table) esecuzione corretta 
               (NULL) situazioni erronee 
*/
hashTable_t * createHash(int sizeH);        

/* @description -- cancella tutta la tabella hash liberando la memoria
   @param  ht  -- tabella da cancellare
*/
void deleteHash(hashTable_t * ht);        

/* @description -- hashFunction
   @param s -- stringa su cui calcolare l'hash
   @param ht -- ampiezza della HashTable
   @returns -- (-1) si sono verificati errori
               ( 0 <= n < (ht->size) ) valore dell'hash
*/
int hashFunction (uint32_t key, hashTable_t* ht);     

/* @description -- inserisce (key, valore) nell' hash table se non c'e' gia'
   @param s -- key 
   @param value -- valore
   @param ht -- puntatore alla hashTable
   @returns -- (NULL) si sono verificati errori (elemento gia' presente etc)
               (!NULL) altrimenti  (***MODIFICATO RISPETTO A FRAM1 **)
*/
void insertHash(hashTable_t* ht, char* protocol, uint32_t key, char *ipSrc, char *ipDst, uint16_t srcPort, uint16_t dstPort, uint32_t bytes, time_t timestamp);
  

/* @description -- rimuove un elemento dall'hash
   @param s -- chiave
   @param ht -- puntatore alla hashTable
   @returns -- (NULL) si sono verificati errori
               (p) puntatore all'elemento rimosso
*/
void removeFromHash (hashTable_t* ht, int step, time_t now);

/* @description -- stampa formattata di un elemento dell'hash
   @param e -- puntatore elemento da stampare 
   @returns -- (-1) si sono verificati errori
               (n>=0) se OK
*/
int printHashElement (FILE * uscita, hashElement_t * e);

/* @description -- dealloca la memoria di un elemento
   @param e -- puntatore elemento da deallocare
*/
void deleteHashElement (hashElement_t * e);





