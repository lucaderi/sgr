#include "mathUtil.h"

u_int32_t roundup_to_2_power(u_int32_t v){
  /*
   * take from :
   * http://graphics.stanford.edu/~seander/bithacks.html
   */
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  
  return v;
}
