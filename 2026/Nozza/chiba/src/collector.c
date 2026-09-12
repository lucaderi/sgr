#include "collector.h"
#include "nf9_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>


/* Socket lifecycle*/

void *get_in_addr(struct sockaddr *sa) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

int set_nonblocking_fd(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { 
        fprintf(stderr, "fcntl F_GETFL\n"); return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "fcntl F_SETFL\n"); return -1;
    }
    return 0;
}

int init_collector_socket() {
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE;
    if (((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1) {
            fprintf(stderr, "socket failed\n"); 
            continue;
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            fprintf(stderr, "bind failed: %s\n", strerror(errno));
            continue;
        }
        break;
    }
    
    freeaddrinfo(servinfo);
    
    if (p == NULL) {
        fprintf(stderr, "failed to bind socket\n");
        return -1;
    }    

    if (set_nonblocking_fd(sockfd) != 0) {
        fprintf(stderr, "failed to set non-blocking socket\n");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void *collector_thread_routine(void *args) {
    ct_data *ctd = (ct_data *) args;
    struct sockaddr_storage their_addr; 
    socklen_t addr_len;
    uint8_t buf[MAXBUFLEN]; 
    ssize_t numbytes;       
    
    struct pollfd pfd;
    pfd.fd     = ctd->sockfd;
    pfd.events = POLLIN;
    while (1) {
        /* The collector thread must drain the socket 
         * completely before it is allowed to exit. */
        int timeout = running_flag ? 1000 : 0;
        
        int rtval = poll(&pfd, 1, timeout);
        if (rtval < 0) {
            if (errno == EINTR) continue;
            else {
                fprintf(stderr, "polling failed: %s\n", strerror(errno));
                break;
            }
        }
        if (rtval == 0) {
            if (running_flag == 0) break;
            continue;
        }

        if (pfd.revents & POLLIN) {
            addr_len = sizeof their_addr;
            if ((numbytes = recvfrom(ctd->sockfd, buf, MAXBUFLEN, 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (running_flag == 0) break;
                fprintf(stderr, "recvfrom\n");
                continue;
            }

            parse_nf9_packet((const u_int8_t *)buf, numbytes, ctd->buffer);
        }    
    }
    return NULL;
}