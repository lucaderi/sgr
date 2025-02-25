#define _GNU_SOURCE   
#include <stdio.h>    
#include <stdlib.h>  
#include <stdbool.h> 
#include <assert.h>  
#include <string.h>   
#include <errno.h>  
#include <math.h>
#include "./nDPI/src/include/ndpi_api.h"

int ndpi_predict_linear(u_int32_t *values, u_int32_t num_values,
			u_int32_t predict_period, u_int32_t *predicted_value,
			float *c, float *m) {
  u_int i;
  float meanX, meanY, meanXY, stddevX, stddevY, covariance, r, alpha, beta;
  struct ndpi_analyze_struct a, b, d;

  if(!values || predict_period < 1 || num_values < 2)
    return -1;

  ndpi_init_data_analysis(&a, 0);
  ndpi_init_data_analysis(&b, 0);
  ndpi_init_data_analysis(&d, 0);

  /* Add values */
  for(i=0; i<num_values; i++){
    ndpi_data_add_value(&a, i);
    ndpi_data_add_value(&b, values[i]);
    ndpi_data_add_value(&d, i * values[i]);
  }

  meanX      = ndpi_data_mean(&a);
  meanY      = ndpi_data_mean(&b);
  meanXY     = ndpi_data_mean(&d);
  stddevX    = ndpi_data_stddev(&a);
  stddevY    = ndpi_data_stddev(&b);
  covariance = meanXY - (meanX * meanY);

  if(fpclassify(stddevX) == FP_ZERO || fpclassify(stddevY) == FP_ZERO) {
    ndpi_free_data_analysis(&a, 0);
    ndpi_free_data_analysis(&b, 0);
    ndpi_free_data_analysis(&d, 0);
    return -1;
  }

  r          = covariance / (stddevX * stddevY);
  beta       = r * (stddevY / stddevX);
  alpha      = meanY - (beta * meanX);

  *predicted_value = alpha + (beta * (predict_period + num_values - 1));
  *c = alpha;
  *m = beta;

  ndpi_free_data_analysis(&a, 0);
  ndpi_free_data_analysis(&b, 0);
  ndpi_free_data_analysis(&d, 0);

  return 0;
}
