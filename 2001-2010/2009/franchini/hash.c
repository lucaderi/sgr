/* Header standard */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Header del progetto */
#include "hash.h"


hashTable_t * createHash(int sizeH){

  hashTable_t*  newhash;
  /* Controllo dimensione tabella non negativa */
  if(sizeH<1)
    return NULL;
  /* Allocazione della memoria per una variabile di tipo hashTable_t */
  if (!(newhash=malloc(sizeof(hashTable_t))))
    return NULL;
  /* Allocazione della memoria per una variabile di hashElement_t* */
  if (!(newhash->table=calloc(sizeH,sizeof(hashElement_t*)))){
    free(newhash);
    return NULL;
  }
  newhash->size=sizeH;
  return newhash;

}

void deleteHash(hashTable_t * ht){
  
  hashElement_t* curr, *prev;
  int i=0;

  if(!ht) return;
  /* Scansione dell'array di puntatori */
  for(i=0;i<ht->size;i++){
    curr=prev=ht->table[i];
    /* Iterazione sulla lista di trabocco per la cancellazione degli elementi */
    while(curr){
      prev=curr;
      curr=curr->next;
      deleteHashElement(prev);
    }
  }
  /* Deallocazione della memoria */
  free(ht->table);
  free(ht);

}

void deleteHashElement (hashElement_t * e){

  /* Controllo parametro non nulli */
  if(!e) return;
  /* deallocazione della memoria */
  free(e->protocol);
  free(e->data);
  free(e->src->ip);
  free(e->src);
  free(e->dst->ip);
  free(e->dst);
  free(e);

}

int hashFunction (uint32_t key, hashTable_t* ht){

  /* Controllo parametri non nulli e dimensione lecita stringa */
  if(!ht) return -1; 
  /*  Calcolo della funzione hash */
  return key % ht->size;
}

void insertHash(hashTable_t* ht, char* protocol, uint32_t key, char * ipSrc, char *ipDst, uint16_t srcPort, uint16_t dstPort, uint32_t bytes, time_t timestamp){
  
  int i=0;
  hashElement_t* tmp=NULL, *prev = NULL;
  host_t * src, *dst;
  data_t * data;
  /* Controllo parametri non nulli */
  if(!ht) return;
  /* Controllo elemento gia' presente */
  if(i = hashFunction(key, ht)==-1) return;
  
  tmp = ht->table[i];
  while(tmp){
    if(!strcmp(tmp->protocol, protocol)){
      if((!strcmp(tmp->src->ip, ipSrc) && !strcmp(tmp->dst->ip, ipDst)) || (!strcmp(tmp->src->ip, ipDst) && !strcmp(tmp->dst->ip, ipSrc))){
	if((tmp->src->port == srcPort && tmp->dst->port == dstPort) || (tmp->src->port == dstPort && tmp->dst->port == srcPort)){
	  //aggiorno flusso
	  tmp->data->pkts += 1;
	  tmp->data->bytes += bytes;
	  tmp->data->lst = timestamp;
	  printf("Aggiorno: %s, %s, %s, %d, %d.\n", protocol, ipSrc, ipDst, srcPort, dstPort);
	  return;
	}
      }
    }
    tmp = tmp->next;
  }
  //inserisco
  if(!(src=malloc(sizeof(host_t))))
    return;

  if(!(dst=malloc(sizeof(host_t))))
    return;

  if(!(data=malloc(sizeof(data_t))))
    return;
  /* Allocazione della memoria per una variabile di hashElement_t */
  if(!(tmp=malloc(sizeof(hashElement_t))))
    return;
  
  src->ip = strdup(ipSrc);
  src->port = srcPort;
  dst->ip = strdup(ipDst);
  dst->port = dstPort;

  data->pkts = 1;
  data->bytes = bytes;
  data->fst = timestamp;
  data->lst = timestamp;

  /* Assegnamento al membro key della stringa s */
  if(!(tmp->protocol=strdup(protocol))){
    free(tmp);
    return;
  }
  
  tmp->data = data;
  tmp->src = src;
  tmp->dst = dst;
  
  /* Aggiunta in testa */
  tmp->next=ht->table[i];
  ht->table[i]=tmp;
  printf("Inserisco: %s, %s, %s, %d, %d.\n", protocol, ipSrc, ipDst, srcPort, dstPort);
  return;  
}

void removeFromHash (hashTable_t* ht, int step, time_t now){

  int i=0;
  hashElement_t* curr, *prev;  
  
  if(!ht) return; 
  for(i = 0; i < ht->size; i++){
    curr = ht->table[i];
    prev = ht->table[i];
    while(curr){      
      if((curr->data->lst - curr->data->fst ) > step || (now - curr->data->lst) > step){
	printHashElement(stdout, curr);
	if(curr==prev){
	  ht->table[i] = curr->next;
	  deleteHashElement(curr);
	  curr = ht->table[i];
	  prev = NULL;
	}
	else{
	  prev->next = curr->next;
	  deleteHashElement(curr);
	  curr = prev;
	}
      }
      if(prev!=NULL){
	prev = curr;
	curr = curr->next;           
      }
      else
	prev = curr;
    }
  }
 
}

 int printHashElement (FILE * uscita, hashElement_t * e){
  
  if(!uscita || !e) return -1;
  return fprintf(uscita, "\nElemento rimosso:\nProtocol:%s\nIpSrc:Port -> %s:%d\nIpDst:Port -> %s:%d\nPacket: %d, Bytes: %d\n\n", e->protocol, e->src->ip, e->src->port, e->dst->ip, e->dst->port, e->data->pkts, e->data->bytes);

}
