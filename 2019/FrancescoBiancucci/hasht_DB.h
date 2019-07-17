/**
* @author Biancucci Francesco 545063
* @file hasht_DB.h
* @brief defines hashtable used to store name-mac assosciations
*/
#ifndef HASHT_DB
#define HASHT_DB

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "defines.h"

typedef struct OUI_t{
  uint8_t mac[MACLEN];//mac
  int submac;//mask
  char* nome;//associated name
  struct OUI_t* next;
}OUI_t;

typedef struct hash_DB{
  int nbuckets;
  OUI_t** buckets;
}hash_DB;

hash_DB* hash_create_DB(int nbuckets);
int hash_destroy_DB(hash_DB* ht);
OUI_t* insert_OUI(hash_DB *ht, char* mac, char* nome);
OUI_t* find_OUI(hash_DB *ht, uint8_t* mac);

#endif
