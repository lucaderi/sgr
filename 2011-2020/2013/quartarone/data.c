#ifndef _DATA_H_
#define _DATA_H_

#include "data.h"
#include <strings.h>


volatile int data_index = 0;
data_collector_t databuff[2];

data_collector_t *get_data_collector(){
  data_collector_t *ret;
  // lock
  ret = &databuff[data_index];
  return ret;
}


data_collector_t *swap_data(){
  data_collector_t *data;
  int tmpi = data_index;
  data_index = data_index ^ 1;
//lock
  data = &databuff[tmpi];
  return data;
}

void init_data(){
  bzero(&databuff, 2*sizeof(data_collector_t));
  //lock
}

#endif
