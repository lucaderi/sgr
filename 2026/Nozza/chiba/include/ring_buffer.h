#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include "wrappers.h"
#include "flow.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#define RING_BUFFER_SIZE 32768

typedef struct ring_buffer {
    pthread_mutex_t lock;
    flow_data *buffer;
    size_t size;
    size_t nelem;    
    size_t head;
    size_t tail;
} rbuffer;

int ring_buffer_init(rbuffer *rb);
void ring_buffer_destroy(rbuffer *rb);

void ring_buffer_put(rbuffer *rb, flow_data rbd);

#endif