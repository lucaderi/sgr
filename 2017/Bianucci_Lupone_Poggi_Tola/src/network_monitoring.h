/* *******************************************
Private def for "network_monitoring.c"
********************************************* */

#ifndef __NETWORK_MONITORING_H__
#define __NETWORK_MONITORING_H__ 001

#include "Global.h"

extern pthread_t tput;

extern void *ThreadPut(void *arg);

extern void sigproc(int sig);
extern char *etheraddr_string(const u_char *ep, char *buf);
extern char *proto2str(u_short proto);
extern char *_intoa(unsigned int addr, char *buf, u_short bufLen);
extern char *intoa(unsigned int addr);
extern long delta_time(struct timeval *now, struct timeval *before);

/**************************************************************************/

/**************************************************************************/

#endif
