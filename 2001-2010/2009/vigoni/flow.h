/*
 * flow.h
 *
 *  Created on: 30-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#ifndef FLOW_H_
#define FLOW_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "capture.h"

#define FLOW_EXPIRE_TIME 60 /* 1 minutes */
char errflow[256];

typedef struct flow
{
	u_int flow_id;
	u_int hash_key;
	struct in_addr ip1, ip2;
	u_short port1, port2;
	u_int tot_pkt;
	u_int tot_byte;
	time_t start, end, last_update;

	pthread_rwlock_t sem;
} flow_t;

/*** Meta ******************************************************************************* ***/

struct meta_flow
{
	u_int hash_key;
	in_addr_t ip1, ip2;
	u_short port1, port2;
};

/* Get the meta-information for packet
 *
 * @param packet_t*
 *
 * @return a pointer to the meta_flow struct that contain the meta information for the packet_t
 */
struct meta_flow* flow_get_meta(packet_t* p);

/*** ************************************************************************************ ***/

/* Create a new flow from packet
 *
 * @param packet_t*
 *
 * @return a pointer to the created flow
 */
flow_t* flow_create(struct meta_flow* meta, packet_t* p);

/* Delete selected flow
 *
 * @param flow_t*
 *
 * @return 1 for success, 0 otherwise
 */
int flow_delete(flow_t* f);

/* Update flow from packet
 *
 * @param flow_t*
 * @param packet_t*
 * @param moeta_flow*
 *
 * @return 1 for success, 0 otherwise
 */
int flow_update(flow_t* f, packet_t* p, struct meta_flow* meta);

/* Check if selected flow is expired
 *
 * @param flow_t*
 *
 * @return 1 if selected flow is expired, 0 otherwise
 */
int flow_is_expired(flow_t* f);

/* Update the estimated time
 *
 * @param time_t
 *
 */
void flow_update_time(time_t t);

/* Get the estimated time
 *
 * @return the timestamp of the estmated time
 */
time_t flow_estimate_time();

/* Calculate the hash key for the target packet
 *
 * @param packet_t*
 *
 * @return the hash key for the target packet
 */
u_int flow_hash_key(packet_t* p);

/*** ************************************************************************************ ***/

#endif /* FLOW_H_ */
