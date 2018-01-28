/*
 * rrd.h
 *
 *  Created on: 18-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#ifndef RRD_H_
#define RRD_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define STEP 1	/* step time in seconds (used for RRD update) */

/* filename definitions */
#define RRD_GRAPH_COUNTER_FILENAME "vigoni_counter_graph.png"
#define RRD_GRAPH_TRAFFIC_FILENAME "vigoni_trafic_graph.png"
#define RRD_DS_FILENAME "vigoni_counter.rrd"

#endif /* RRD_H_ */

/* update the rrd */
int rrdupdate(u_int tcp_size, u_int udp_size, u_int tcp_count, u_int udp_count);

/* save graphs */
int rrdsave();

/* Crea il database RRD */
int rrdcreate();
