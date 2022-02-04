#ifndef __LOG_H__
#define __LOG_H__

typedef enum {
    L_DEBUG = 3,
    L_INFO = 2,
    L_WARN = 1,
    L_ERROR = 0
} loglevel_t;

void LOG_SET_LEVEL();

void LOG(loglevel_t level, char* format, ...);
void LOG_ERRNO(loglevel_t level, char* format, ...);

#endif
