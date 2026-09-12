#ifndef COLLECTOR_H
#define COLLECTOR_H

#include "ring_buffer.h"

#define PORT "9995"
#define MAXBUFLEN 2048

#include <sys/socket.h>
#include <signal.h>

typedef struct collector_thread_data {
    int sockfd;
    rbuffer *buffer;
} ct_data;

extern volatile sig_atomic_t running_flag;

/* Given a sockaddr (structure describing a generic socket address), 
 * this function returns its IPv4 socket address */
void *get_in_addr(struct sockaddr *sa);

/* Given a file descriptor, this function sets it to non-blocking mode. 
 * 0 is return on success, -1 otherwise */
int set_nonblocking_fd(int fd);

/* Given a port, this function listens on socket file descriptor, 
 * establishes a new connection on it and performs the binding. 
 * On success, the opened socket file descriptor is returned. */
int init_collector_socket();

/* This routine implements the packets collection logic by processing NF5 packets 
 * and by producing them on a ring bounded buffer */
 void *collector_thread_routine(void *args); 

#endif 