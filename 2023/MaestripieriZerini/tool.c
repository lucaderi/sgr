#define _GNU_SOURCE   
#include <stdio.h>    
#include <stdlib.h>  
#include <stdbool.h> 
#include <assert.h>  
#include <string.h>   
#include <errno.h>  
#include <math.h>
#include <unistd.h>
#include "./nDPI/src/include/ndpi_api.h"

extern int ndpi_predict_linear(u_int32_t *values, u_int32_t num_values,
			       u_int32_t predict_period, u_int32_t *predicted_value,
			       float *c, float *m);

void testTool() {
  int i;
  FILE *fp;
  char memTotal[15], memFree[15], buffers[15], cached[15];
  u_int32_t mem[10];

  printf("Collecting data every 10 seconds...\n");
  for(i=0; i<10; i++){
    fp = popen("grep MemTotal /proc/meminfo | awk '{print $2}'", "r");
    if(fgets(memTotal, sizeof(memTotal), fp) == NULL)
      return;
    pclose(fp);
    fp = popen("grep MemFree /proc/meminfo | awk '{print $2}'", "r");
    if(fgets(memFree, sizeof(memFree), fp) == NULL)
      return;
    pclose(fp);
    fp = popen("grep Buffers /proc/meminfo | awk '{print $2}'", "r");
    if(fgets(buffers, sizeof(buffers), fp) == NULL)
      return;
    pclose(fp);
    fp = popen("grep Cached /proc/meminfo | awk '{print $2}'", "r");
    if(fgets(cached, sizeof(cached), fp) == NULL)
      return;
    pclose(fp);
    mem[i] = atoi(memTotal) - atoi(memFree) - atoi(buffers) - atoi(cached);
		
    printf("Istant: %d, Busy memory: %d KB\n", i, mem[i]);
    sleep(10);
  }

  u_int32_t predicted_value;
  float c, m;
  int ret_val;
  ret_val = ndpi_predict_linear(mem, 10, 6, &predicted_value, &c, &m);
  if(ret_val == 0){
    printf("Computation OK\n");
  }else{
    printf("Error in computation\n");
  }
  printf("The y-intercept is: %f\n", c);
  printf("The slope is: %f\n", m);
  printf("The predicted value is: %d\n", predicted_value);
}

int main(int argc, char *argv[]){
  testTool();
  return 0;
}
