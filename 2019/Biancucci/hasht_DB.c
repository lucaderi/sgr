/**
* @author Biancucci Francesco 545063
* @file hasht_DB.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "defines.h"
#include "hasht_DB.h"


/**
* @fn hash_create_DB
* @brief creates the hashtable
*/
hash_DB* hash_create_DB(int nbuckets){
    hash_DB* ht;
    int i;

    ht = (hash_DB*) calloc(1, sizeof(hash_DB));
    if(!ht) return NULL;
    ht->buckets = (OUI_t**)malloc(nbuckets * sizeof(OUI_t*));
    if(!ht->buckets) return NULL;

    ht->nbuckets = nbuckets;
    for(i=0;i<ht->nbuckets;i++)
        ht->buckets[i] = NULL;

    return ht;
}

/**
* @fn hash_destroy_DB
* @brief destroys the hashtable
*/
int hash_destroy_DB(hash_DB *ht){
    OUI_t *bucket, *curr, *next;
    int i;

    if(!ht) return -1;

    for (i=0; i<ht->nbuckets; i++) {
        bucket = ht->buckets[i];
        for (curr=bucket; curr!=NULL;) {
            next=curr->next;
            free(curr->nome);
            free(curr);
            curr=next;
        }
    }

    if(ht->buckets) free(ht->buckets);
    if(ht) free(ht);

    return 0;
}

/**
* @fn insert_OUI
* @brief insert an assosiaction mac-name
*/
OUI_t* insert_OUI(hash_DB *ht, char* mac, char* nome){
    OUI_t* curr;
    if(!ht || !mac || !nome) return NULL;
    unsigned char macu[MACLEN];
    int submac=0;
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx/%d", &macu[0], &macu[1], &macu[2], &macu[3], &macu[4], &macu[5], &submac);

    uint32_t i32;
    i32 &= 0;
    i32 = macu[0] | (macu[1] << 8) | (macu[2] << 16);
    i32 = i32 % ht->nbuckets;

    /* for sure every key is different */
    curr = (OUI_t*)calloc(1, sizeof(OUI_t));
    if(!curr) return NULL;

    memcpy(curr->mac, macu, MACLEN);
    curr->submac=submac;
    curr->nome= calloc(strlen(nome), sizeof(char));
    memcpy(curr->nome, nome, strlen(nome));

    /* add at start */
    curr->next = ht->buckets[i32];
    ht->buckets[i32] = curr;

    return curr;
}

/**
* @fn find_OUI
* @brief retrieves the association
*/
OUI_t* find_OUI(hash_DB *ht, uint8_t* mac){
  OUI_t* curr;
  if(!ht || !mac) return NULL;

  uint32_t i32;
  i32 &= 0;
  i32 = mac[0] | (mac[1] << 8) | (mac[2] << 16);
  i32 = i32 % ht->nbuckets;
  for (curr=ht->buckets[i32]; curr != NULL; curr=curr->next)
    if (curr->mac[0]==mac[0] && curr->mac[1]==mac[1] && curr->mac[2]==mac[2])
          return(curr);
  return NULL;
}
