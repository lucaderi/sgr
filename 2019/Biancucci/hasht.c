/**
* @author Biancucci Francesco 545063
* @file hasht.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "defines.h"
#include "hasht.h"


/**
* @fn hash_create_dev
* @brief creates the hashtable
*/
hash_t* hash_create_dev(int nbuckets){
    hash_t* ht;
    int i;

    ht = (hash_t*) calloc(1, sizeof(hash_t));
    if(!ht) return NULL;
    ht->nentries=0;
    ht->buckets = (device**)malloc(nbuckets * sizeof(device*));
    if(!ht->buckets) return NULL;

    ht->nbuckets = nbuckets;
    for(i=0;i<ht->nbuckets;i++)
        ht->buckets[i] = NULL;

    return ht;
}

/**
* @fn hash_destroy_dev
* @brief destroys the hashtable
*/
int hash_destroy_dev(hash_t *ht){
    device *bucket, *curr, *next;
    int i;

    if(!ht) return -1;

    for (i=0; i<ht->nbuckets; i++) {
        bucket = ht->buckets[i];
        for (curr=bucket; curr!=NULL;) {
            next=curr->next;
            if(curr->nome)  free(curr->nome);
            free(curr);
            curr=next;
        }
    }

    if(ht->buckets) free(ht->buckets);
    if(ht) free(ht);

    return 0;
}

/**
* @fn insertself_device
* @brief insert the device used to scan
*/
device *insertself_device(hash_t *ht, uint8_t* ip, uint8_t *mac){
    device *curr;
    if(!ht || !mac) return NULL;
    uint32_t i32;
    i32&=0;
    i32 = mac[0] | (mac[1] << 8) | (mac[2] << 16);
    i32 = i32 % ht->nbuckets;
    /* key not found for sure */
    curr = (device*)calloc(1, sizeof(device));
    if(!curr) return NULL;

    memcpy(curr->ip, ip, IPV4LEN);
    memcpy(curr->mac, mac, MACLEN);

    curr->nome=NULL;
    curr->new=1;
    curr->disconnected=-1;
    /* add at start */
    curr->next = ht->buckets[i32];
    ht->buckets[i32] = curr;
    ht->nentries++;
    return curr;
}

/**
* @fn insert_device
* @brief insert any device scanned
*/
device *insert_device(hash_t *ht, uint8_t* ip, uint8_t *mac){
    device *curr;
    if(!ht || !mac) return NULL;
    uint32_t i32;
    i32 &= 0;
    i32 = mac[0] | (mac[1] << 8) | (mac[2] << 16);
    i32 = i32 % ht->nbuckets;

    for (curr=ht->buckets[i32]; curr != NULL; curr=curr->next){
        if (curr->ip[0]==ip[0] && curr->ip[1]==ip[1] && curr->ip[2]==ip[2] && curr->ip[3]==ip[3]){
            curr->disconnected = 0;
            return(NULL); /* key already exists */
        }
    }
    /* if key was not found */
    curr = (device*)calloc(1, sizeof(device));
    if(!curr) return NULL;

    memcpy(curr->ip, ip, IPV4LEN);
    memcpy(curr->mac, mac, MACLEN);

    curr->nome = NULL;
    curr->new=1;
    curr->disconnected=0;
    /* add at start */
    curr->next = ht->buckets[i32];
    ht->buckets[i32] = curr;
    ht->nentries++;
    return curr;
}

/**
* @fn find_device
* @brief finds a device in the hashtable and associates a brand name to it
*/
device* find_device(hash_t *ht, uint8_t* ip, uint8_t* mac, char* nome){
    device* curr;

    if(!ht || !mac) return NULL;

    uint32_t i32;
    i32 &= 0;

    i32 = mac[0] | (mac[1] << 8) | (mac[2] << 16);
    i32 = i32 % ht->nbuckets;

    for (curr=ht->buckets[i32]; curr != NULL; curr=curr->next)
      if (curr->ip[0]==ip[0] && curr->ip[1]==ip[1] && curr->ip[2]==ip[2] && curr->ip[3]==ip[3]){
        curr->nome = calloc(strlen(nome), sizeof(char));
        memcpy(curr->nome, nome, strlen(nome));
        return(curr);
      }

    return NULL;
}

/**
* @fn get_list_device
* @brief return a list of all devices
*/
device** get_list_device(hash_t* ht, int* dim){
  device** list = calloc(ht->nentries, sizeof(device*));
  for(int i = 0; i < ht->nentries; i++)
    list[i] = calloc(1, sizeof(device));
  device* curr;
  int listindex=0;
  for(int i=0; i<ht->nbuckets; i++){
    for (curr=ht->buckets[i]; curr != NULL; curr=curr->next){
      memcpy(list[listindex], curr, sizeof(device));
      if(curr->disconnected!=-1) curr->disconnected++;
      curr->new=0;
      listindex++;
    }

  }
  *dim=listindex;
  return list;
}

/**
* @fn delete_device
* @brief remove a device from the hashtable
*/
int delete_device(hash_t *ht, uint8_t* ip, uint8_t* mac){
    device *curr, *prev;

    if(!ht || !mac) return -1;
    uint32_t i32;
    i32&=0;

    i32 = mac[0] | (mac[1] << 8) | (mac[2] << 16);
    i32 = i32 % ht->nbuckets;

    prev = NULL;
    for (curr=ht->buckets[i32]; curr != NULL; )  {
      if (curr->ip[0]==ip[0] && curr->ip[1]==ip[1] && curr->ip[2]==ip[2] && curr->ip[3]==ip[3]){
            if (prev == NULL) {
                ht->buckets[i32] = curr->next;
            } else {
                prev->next = curr->next;
            }
            if(curr->nome) free(curr->nome);
            free(curr);
            ht->nentries--;
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }
    return -1;
}
