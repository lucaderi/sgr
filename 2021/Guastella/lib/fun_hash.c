#include <stdlib.h> 
#include <string.h>
#include <limits.h>
#include "count_min_sketch.h"

 unsigned long  hash_fnv_1a(const char* key) {
    
    int i, len = strlen(key);
    unsigned long h = 14695981039346656073ULL; // FNV_OFFSET 64 bit
    for (i = 0; i < len; ++i){
            h = h ^ (unsigned char) key[i];
            h = h * 1099511628211ULL; // FNV_PRIME 64 bit
    }
    return h;
}
//*************murmur3************************************************
 u_int32_t fmix32 ( u_int32_t h )
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}

 u_int32_t rotl32 ( u_int32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}


 u_int32_t getblock32 ( const u_int32_t * p, int i )
{
  return p[i];
}
//*************************************************************************

u_int32_t MurmurHash3 ( const void * key, int len, u_int32_t seed ){
  
  const u_int8_t * data = (const u_int8_t*)key;
  const int nblocks = len / 4;

  u_int32_t h1 = seed;

  const u_int32_t c1 = 0xcc9e2d51;
  const u_int32_t c2 = 0x1b873593;

  const u_int32_t * blocks = (const u_int32_t *)(data + nblocks*4);

  for(int i = -nblocks; i; i++) {
      u_int32_t k1 = getblock32(blocks,i);

      k1 *= c1;
      k1 = rotl32(k1,15);
      k1 *= c2;
      
      h1 ^= k1;
      h1 = rotl32(h1,13); 
      h1 = h1*5+0xe6546b64;
  }

  const u_int8_t * tail = (const u_int8_t*)(data + nblocks*4);

  u_int32_t k1 = 0;

  switch(len & 3){
      case 3: k1 ^= tail[2] << 16;
      case 2: k1 ^= tail[1] << 8;
      case 1: k1 ^= tail[0];
              k1 *= c1; k1 = rotl32(k1,15); k1 *= c2; h1 ^= k1;
  };

  h1 ^= len;

  h1 = fmix32(h1);

  return h1;
} 

//***********************************************************************************************


void hash_function(const char* key, u_int32_t depth, u_int32_t *a, u_int32_t *b ){
    
       unsigned long a1 = MurmurHash3(key,strlen(key), 479001599);
       unsigned long b1 = hash_fnv_1a(key);

       *a = a1%depth;
       *b = b1 % depth;   
}


u_int32_t hash_increment(u_int32_t depth, u_int32_t *a, u_int32_t *b, int i){
  return(((*a^i + (*b)) )% depth);
}