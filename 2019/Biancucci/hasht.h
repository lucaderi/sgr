/**
* @author Biancucci Francesco 545063
* @file hasht.h
* @brief defines hashtable used to save scanned devices
*/
#ifndef HASHT_H
#define HASHT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>


#include "defines.h"

typedef struct device{
  uint8_t ip[IPV4LEN];//device ip
  uint8_t mac[MACLEN];//device mac
  char *nome;//device name
  int new;//first time seen in the scan
  int disconnected;//not seen, probably disconnected
  struct device* next;
}device;

typedef struct hash_t{
  int nbuckets;//hasht number of buckets
  int nentries;//hasht number of elements
  device** buckets;
}hash_t;

hash_t* hash_create_dev(int nbuckets);
int hash_destroy_dev(hash_t* ht);
device *insertself_device(hash_t *ht, uint8_t* ip, uint8_t *mac);
device* insert_device(hash_t *, uint8_t*, uint8_t*);
device* find_device(hash_t *ht, uint8_t* ip, uint8_t* mac, char* nome);
int delete_device(hash_t *ht, uint8_t* ip, uint8_t* mac);
device** get_list_device(hash_t* ht, int* dim);

#endif
