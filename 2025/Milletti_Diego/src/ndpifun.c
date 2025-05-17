/*
 * Questo file contiene una selezione di codice importato da nDPI.
 * Sono state incluse solo le funzioni strettamente necessarie al calcolo
 * di statistiche sulla finestra TCP, con l'obiettivo di ridurre al minimo
 * l'utilizzo di memoria nei file PCAP di grandi dimensioni.
 */

#include <stdlib.h>    // malloc, calloc, free
#include <string.h>    // memset
#include <stdint.h>    // uint64_t, uint32_t, uint16_t, ecc.
#include <math.h>      // pow, sqrt

#define MAX_SERIES_LEN 512

#define ndpi_min(a,b)   ((a < b) ? a : b)

/* ****************************************** */

/* https://stackoverflow.com/questions/7993050/multiplatform-atomic-increment
per un uso su windows */
#ifdef _WIN32
#include <windows.h> 
#define __sync_fetch_and_add(a,b) InterlockedExchangeAdd ((a), b)
#endif

/* ****************************************** */

struct ndpi_analyze_struct {
    u_int64_t *values;
    u_int64_t min_val, max_val, sum_total, jitter_total;
    u_int32_t num_data_entries, next_value_insert_index;
    u_int16_t num_values_array_len /* length of the values array */;
  
    struct {
      u_int64_t sum_square_total;
    } stddev;
  };

static void *(*_ndpi_malloc)(size_t size);
static void (*_ndpi_free)(void *ptr);

static volatile long int ndpi_tot_allocated_memory;

/* ****************************************** */

u_int32_t ndpi_get_tot_allocated_memory() {
  return(__sync_fetch_and_add(&ndpi_tot_allocated_memory, 0));
}

/* ****************************************** */
  
 void *ndpi_malloc(size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size));
}
  
/* ****************************************** */

void *ndpi_calloc(unsigned long count, size_t size) {
  size_t len = count * size;
  void *p = _ndpi_malloc ? _ndpi_malloc(len) : malloc(len);

  if(p) {
    memset(p, 0, len);
    __sync_fetch_and_add(&ndpi_tot_allocated_memory, len);
  }

  return(p);
}
  
/* ****************************************** */

void ndpi_free(void *ptr) {
  if(_ndpi_free) {
    if(ptr)
      _ndpi_free(ptr);
  } else {
    if(ptr)
      free(ptr);
  }
}

/* ****************************************** */

void ndpi_init_data_analysis(struct ndpi_analyze_struct *ret, u_int16_t _max_series_len) {
    memset(ret, 0, sizeof(*ret));
  
    if(_max_series_len > MAX_SERIES_LEN) _max_series_len = MAX_SERIES_LEN;
    ret->num_values_array_len = _max_series_len;

    if(ret->num_values_array_len > 0) {
        if((ret->values = (u_int64_t *)ndpi_calloc(ret->num_values_array_len,
                                sizeof(u_int64_t))) == NULL)
        ret->num_values_array_len = 0;
    }
}

/* ****************************************** */

struct ndpi_analyze_struct* ndpi_alloc_data_analysis(u_int16_t _max_series_len) {
    struct ndpi_analyze_struct *ret = ndpi_malloc(sizeof(struct ndpi_analyze_struct));
  
    if(ret != NULL)
      ndpi_init_data_analysis(ret, _max_series_len);
  
    return(ret);
  }

/* ****************************************** */

  void ndpi_free_data_analysis(struct ndpi_analyze_struct *d, u_int8_t free_pointer) {
    if(d && d->values) ndpi_free(d->values);
    if(free_pointer) ndpi_free(d);
  }

/* ****************************************** */

  void ndpi_reset_data_analysis(struct ndpi_analyze_struct *d) {
    u_int64_t *values_bkp;
    u_int32_t num_values_array_len_bpk;
  
    if(!d)
      return;
  
    values_bkp = d->values;
    num_values_array_len_bpk = d->num_values_array_len;
  
    memset(d, 0, sizeof(struct ndpi_analyze_struct));
  
    d->values = values_bkp;
    d->num_values_array_len = num_values_array_len_bpk;
  
    if(d->values)
      memset(d->values, 0, sizeof(u_int64_t)*d->num_values_array_len);
  }

  u_int64_t ndpi_data_last(struct ndpi_analyze_struct *s) {
    if((!s) || (s->num_data_entries == 0) || (s->num_values_array_len == 0))
      return(0);
  
    if(s->next_value_insert_index == 0)
      return(s->values[s->num_values_array_len-1]);
    else
      return(s->values[s->next_value_insert_index-1]);
  }

/* ****************************************** */

  void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int64_t value) {
    if(!s)
      return;
  
    if(s->num_data_entries > 0) {
      u_int64_t last = ndpi_data_last(s);
  
      s->jitter_total += (last > value) ? (last - value) : (value - last);
    }
  
    if(s->sum_total == 0)
      s->min_val = s->max_val = value;
    else {
      if(value < s->min_val) s->min_val = value;
      if(value > s->max_val) s->max_val = value;
    }
  
    s->sum_total += value, s->num_data_entries++;
  
    if(s->num_values_array_len) {
      s->values[s->next_value_insert_index] = value;
  
      if(++s->next_value_insert_index == s->num_values_array_len)
        s->next_value_insert_index = 0;
    }
  
    /*
      Optimized stddev calculation
  
      https://www.khanacademy.org/math/probability/data-distributions-a1/summarizing-spread-distributions/a/calculating-standard-deviation-step-by-step
      https://math.stackexchange.com/questions/683297/how-to-calculate-standard-deviation-without-detailed-historical-data
      http://mathcentral.uregina.ca/QQ/database/QQ.09.02/carlos1.html
    */
    s->stddev.sum_square_total += (u_int64_t)value * (u_int64_t)value;
  }

/* ****************************************** */

/* Return min/max on all values */
u_int64_t ndpi_data_min(struct ndpi_analyze_struct *s) { return(s ? s->min_val : 0); }
u_int64_t ndpi_data_max(struct ndpi_analyze_struct *s) { return(s ? s->max_val : 0); }

/* ****************************************** */

/* Compute the variance on all values */
float ndpi_data_variance(struct ndpi_analyze_struct *s) {
  if(!s)
    return(0);
  float v = s->num_data_entries ?
    ((float)s->stddev.sum_square_total - ((float)s->sum_total * (float)s->sum_total / (float)s->num_data_entries)) / (float)s->num_data_entries : 0.0;

  return((v < 0  /* rounding problem */) ? 0 : v);
}

/* ****************************************** */

/*
  See the link below for "Population and sample standard deviation review"
  https://www.khanacademy.org/math/statistics-probability/summarizing-quantitative-data/variance-standard-deviation-sample/a/population-and-sample-standard-deviation-review

  In nDPI we use an approximate stddev calculation to avoid storing all data in memory
*/
/* Compute the standard deviation on all values */
float ndpi_data_stddev(struct ndpi_analyze_struct *s) {
  return(sqrt(ndpi_data_variance(s)));
}

/* ****************************************** */

/* Compute the average on all values */
float ndpi_data_average(struct ndpi_analyze_struct *s) {
    if((!s) || (s->num_data_entries == 0))
      return(0);
  
    return((float)s->sum_total / (float)s->num_data_entries);
  }

/* ****************************************** */

/*
   Compute the mean on all values
   NOTE: In statistics, there is no difference between the mean and average
*/
float ndpi_data_mean(struct ndpi_analyze_struct *s) {
  return ndpi_data_average(s);
}

/* ****************************************** */
  