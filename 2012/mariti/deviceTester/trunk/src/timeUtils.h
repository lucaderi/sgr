#ifndef DEVICETESTER_TIMEUTIL_H
#define DEVICETESTER_TIMEUTIL_H
#include <sys/time.h>
#include <time.h>

#ifndef usec_t_defined
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <sys/types.h>
#define usec_t_defined
typedef u_int64_t  usec_t;
/* ??? */
#define USEC_T_MAX ULONG_MAX
#define PRI_USEC "%llu"
#endif

/**
 * usec_t timeval2usec(stuct timeval *t)
 *
 * convert struct timeval time value to microsecond time value
 */
#define timeval2usec(t) \
  (usec_t)((t)->tv_sec * 1000000 + (t)->tv_usec)

/**
 * void usec2timeval(usec_t t, struct timeval *result);
 *
 * convert microsecond time value to struct timeval time value
 */
#define usec2timeval(t, result) \
  (result)->tv_sec = (t) / 1000000; (result)->tv_usec = (t) % 1000000;

/**
 * void usec2timespec(usec_t t, struct timespec *resutl);
 *
 * convert microsecond time value to struct timeval time value
 */
#define usec2timespec(t, result) \
  (result)->tv_sec = (t) / 1000000; (result)->tv_nsec = (t) % 1000000000;

/**
 * return the result of the difference between two timeval value, in
 * microseconds
 */
usec_t usec_timevalsub(struct timeval *t1, struct timeval *t2);

/**
 * return the absolute value of the difference between two timeval
 * value, in microseconds
 */
usec_t usec_timeval_abs_sub(struct timeval *t1, struct timeval *t2);

/**
 *
 */
#define timeval2msec(t) \
  (double)((t)->tv_sec * 1000 + (double)(t)->tv_usec / 1000)

/**
 * 
 */
double msec_timevalsub(struct timeval *t1, struct timeval *t2);

#endif	/* DEVICETESTER_TIMEUTIL_H */
