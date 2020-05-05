#include "memUtil.h"

void * calloc_wrapper(unsigned long size){
  return calloc(1, size);
}

void free_wrapper(void * freeable){
  free(freeable);
}
