#ifndef TIMER_H_
#define TIMER_H_

#include <event.h>
#include "flow.h"

#define CMD_NO 3
#define VAL_LEN 34
#define MAX_FLOW_DURATION 1800 /* seconds (30 minutes) */
#define MAX_FLOW_INACTIVITY 15 /* seconds */

#define PRINT_EXPORTED_FLOWS

void rrd_updater(int fd, short event, void *ud);
/* collects expired flows from the flow cache and puts them into the "cemetery"
 * a data structure needed to perform delayed frees securely */
void undertaker(int fd, short event, void *ud);
/* prints flows on standard output */
void exportFlow(t_flow_ID *flowID, t_flow_info *flowInfo);
/* the thread that regularly calls the functions that update RRD and clean the flow cache */
void *timer(void *arg);

#endif /* TIMER_H_ */
