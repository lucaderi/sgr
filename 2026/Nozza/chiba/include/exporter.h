#ifndef EXPORTER_H
#define EXPORTER_H  

#include "ring_buffer.h"
#include "flow.h"

#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <curl/curl.h>

/* The linear export buffer 
 * is dimensioned on ClickHouse writing efficiency
 * and on the optimal throughput of the HTTP payload. 
 * 
 * Double buffering optimization was adopted. 
 * (see ring_buffer.h for further explanation)
 */
#define EXPORT_BUFFER_SIZE 16384 

#define EXPORT_MIN_TIME_MS 5000U

u_int64_t get_time_ms(void);

typedef struct export_buffer {
    flow_data *buffer;
    size_t size;
    size_t nelem; 
} ebuffer;

CURL *curl_for_ch_init(void);
void curl_for_ch_perform(CURL *curl, ebuffer *eb);

int export_buffer_init(ebuffer *eb);
void export_buffer_destroy(ebuffer *eb);

size_t batch_transfer(rbuffer *rb, ebuffer *eb);

extern volatile sig_atomic_t running_flag;
int export_routine(rbuffer *rb, ebuffer *eb, CURL *curl);
void export_flush(rbuffer *rb, ebuffer *eb, CURL *curl);

#endif

 