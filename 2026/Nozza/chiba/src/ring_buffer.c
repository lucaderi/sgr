#include "ring_buffer.h"

int ring_buffer_init(rbuffer *rb){
    rb->buffer = xmalloc(RING_BUFFER_SIZE * sizeof(flow_data));
    if (rb->buffer == NULL) {
        fprintf(stderr, "insufficient memory for ring buffer initialization\n");
        return -1;
    }

    if (pthread_mutex_init(&rb->lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize ring buffer lock\n");
        free(rb->buffer); return -1;
    }

    rb->size  = RING_BUFFER_SIZE;
    rb->nelem = 0;
    rb->head  = 0;
    rb->tail  = 0;

    return 0;
}

void ring_buffer_destroy(rbuffer *rb) {
    free(rb->buffer);
    pthread_mutex_destroy(&rb->lock);
    free(rb);
}

void ring_buffer_put(rbuffer *rb, flow_data rbd) {
    pthread_mutex_lock(&rb->lock);
    
    rb->buffer[rb->tail] = rbd;
    rb->tail = (rb->tail + 1) & (rb->size - 1);
    rb->nelem++;

    pthread_mutex_unlock(&rb->lock);
}