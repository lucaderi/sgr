#define _GNU_SOURCE   
#include <stdio.h>    
#include <stdlib.h>  
#include <stdbool.h> 
#include <assert.h>  
#include <string.h>   
#include <errno.h>  
#include <math.h>
#include "./nDPI/src/include/ndpi_api.h"

extern int ndpi_predict_linear(u_int32_t *values, u_int32_t num_values,
			       u_int32_t predict_period, u_int32_t *predicted_value,
			       float *c, float *m);

void predictLinearUnitTest(){
	u_int32_t values[] = {15, 27, 38, 49, 68, 72, 90, 150, 175, 203};
	u_int32_t predicted_value;
	float c, m;
	int ret_val;
	ret_val = ndpi_predict_linear(values, 10, 5, &predicted_value, &c, &m);
	if(ret_val == 0){
		printf("Computation OK\n");
	}else{
		printf("Error in computation\n");
	}
	printf("The y-intercept is: %f\n", c);
	printf("The slope is: %f\n", m);
	printf("The predicted value is: %d\n", predicted_value);
}

int main(int argc, char *argv[]) {
	predictLinearUnitTest();
	return 0;
}


