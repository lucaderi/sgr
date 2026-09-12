#include "exporter.h"
#include "config.h"

u_int64_t get_time_ms(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    
    return /* (sec * 1e3) + (nsec / 1e6) */
    (u_int64_t)tp.tv_sec * 1000 + (u_int64_t)tp.tv_nsec / 1000000;   
}

CURL *curl_for_ch_init(void) {
    CURL *curl = curl_easy_init();
    if (curl != NULL) {
        curl_easy_setopt(curl, CURLOPT_URL, global_config.ch_target_url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    }
    return curl;
}

/* Callback function for writing receiving data. 
 * It maches the prototype shown here: 
 * https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html 
 */


static char curl_err_buf[CURL_ERROR_SIZE];
static char ch_resp_body[1024];
static size_t ch_resp_len = 0;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    /* Intentionally unused userdata */
    (void)userdata;
    
    size_t total_size = size * nmemb;
    size_t copy_size = total_size;
    
    /* Bufffer overflow prevention */
    if (ch_resp_len + copy_size >= sizeof(ch_resp_body) - 1) {
        copy_size = sizeof(ch_resp_body) - 1 - ch_resp_len;
    }
    
    if (copy_size > 0) {
        memcpy(ch_resp_body + ch_resp_len, ptr, copy_size);
        ch_resp_len += copy_size;
        ch_resp_body[ch_resp_len] = '\0';
    }
    return total_size;
}

static void curl_for_ch_perform_failure(CURLcode res, size_t npkts) {
    fprintf(stderr, "Network blocking transfer failed: %s\n", curl_easy_strerror(res));
    if (npkts > 0)
        fprintf(stderr, "%zu packets could not be sent to ClickHouse\n", npkts);
}

void curl_for_ch_perform(CURL *curl, ebuffer *eb) {
    ch_resp_len = 0; /* Reset buffer */
    
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, eb->buffer);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)((eb->nelem) * sizeof(flow_data)));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_buf);
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    if (res != CURLE_OK || http_code >= 400) {
        fprintf(stderr, "HTTP %ld - Curl Error: %s\n", http_code, 
                res == CURLE_OK ? "None" : curl_err_buf);
        if (http_code >= 400 && ch_resp_len > 0) {
            fprintf(stderr, "ClickHouse Error: %s\n", ch_resp_body);
        }
        curl_for_ch_perform_failure(res, eb->nelem);
    }
}
 
int export_buffer_init(ebuffer *eb) {
    eb->buffer = xmalloc(EXPORT_BUFFER_SIZE * sizeof(flow_data));
    if (eb->buffer == NULL) {
        fprintf(stderr, "failed with export buffer memory allocation\n");
        return -1;
    }
    eb->size  = EXPORT_BUFFER_SIZE;
    eb->nelem = 0;
    return 0;
}

void export_buffer_destroy(ebuffer *eb) {
    free(eb->buffer);
    free(eb);
}

size_t batch_transfer(rbuffer *rb, ebuffer *eb) {  
    pthread_mutex_lock(&rb->lock);
    
    /* non-blocking */
    if (rb->nelem == 0) {
        pthread_mutex_unlock(&rb->lock);
        return 0;
    }
    size_t eb_residual_cap = eb->size - eb->nelem;
    size_t n = (rb->nelem) > (eb_residual_cap) ? eb_residual_cap : rb->nelem;
    /* NO WRAP-AROUND: n <= av_space (available space in ring buffer). 
     * Single call to memcpy. Source starts at rb->head.
     * WRAP_AROUND: n > av_space => Double call to memcpy needed.
     * The source intervals to cover are 
     * [head, head + av_space] and [0, n - av_space]    
     */
    size_t av_space = rb->size - rb->head;
    size_t rdata_sz = sizeof(flow_data);
    if (n <= av_space) {
        memcpy(&eb->buffer[eb->nelem], &rb->buffer[rb->head], (n * rdata_sz));
    } else {
        memcpy(&eb->buffer[eb->nelem], &rb->buffer[rb->head], (av_space * rdata_sz));
        memcpy(&eb->buffer[(eb->nelem + av_space)], &rb->buffer[0], ((n - av_space) * rdata_sz));       
    }
    
    rb->head  = (rb->head + n) & (rb->size - 1);
    rb->nelem = rb->nelem - n;
    eb->nelem = eb->nelem + n;
    
    pthread_mutex_unlock(&rb->lock);
    return n;
}

int export_routine(rbuffer *rb, ebuffer *eb, CURL *curl) {        
    u_int64_t before, now;
    before = now = get_time_ms();
    while (running_flag) {
        now = get_time_ms();
        u_int64_t delta = now - before;
        
        int batch_ret = 0;
        int sent      = 0;
        if (batch_transfer(rb, eb) > 0) 
            batch_ret = 1; 

        /* Volumetric trigger || Time trigger */
        if (batch_ret && ((eb->nelem >= eb->size) || (delta >= EXPORT_MIN_TIME_MS))) {

            if (eb->nelem > 0) {
                sent = 1;
                curl_for_ch_perform(curl, eb);
                eb->nelem = 0;
            }
            
            now = get_time_ms();
            before = now;
            batch_ret = 0;
        }
        
        /* Sleep management */
        if (!sent && !batch_ret) {
            struct timespec request = { .tv_sec = 0, .tv_nsec = 10000000 /* 10 ms */ };
            nanosleep(&request, NULL);
        }

    }
    
    return 0;
}

void export_flush(rbuffer *rb, ebuffer *eb, CURL *curl) {
    while (batch_transfer(rb, eb) > 0) {
        curl_for_ch_perform(curl, eb);
        eb->nelem = 0;
    }
    if (eb->nelem > 0) {
        curl_for_ch_perform(curl, eb);
        eb->nelem = 0;
    }
}