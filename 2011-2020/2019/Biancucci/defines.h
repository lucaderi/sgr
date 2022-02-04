/**
* @author Biancucci Francesco 545063
* @file defines.h
* @brief defines control macro and const
*/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#ifndef _DEFINES_H
#define _DEFINES_H


#define ETH_HEADERLEN_V2 14 //macdest+macsource+mactype 6+6+2
#define MAXHOST 256
#define TIMEOUT 30

#define IPV4LEN 4
#define MACLEN 6

#define CHECK_NULL(x, s) if ((x) == NULL) { \
                            errno = EINVAL; \
                            perror(#s); \
                            exit(EXIT_FAILURE); }

#define CHECK_ERR(x, y) if((x) < 0){ \
                            perror(#y); \
                            exit(EXIT_FAILURE); }

#define CHECK_ZERO(x, s) if ((x) != 0) { \
                            errno = x; \
                            perror(#s); \
                            exit(EXIT_FAILURE);}

#endif
