/*
 * flow.c
 *
 *  Created on: 31-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#include "flow.h"

time_t estimate_time = 0;

/*** ************************************************************************************ ***/

/* Get the meta-information for packet
 *
 * @param packet_t*
 *
 * @return a pointer to the meta_flow struct that contain the meta information for the packet_t
 */
struct meta_flow* flow_get_meta(packet_t* p)
{
	struct meta_flow* mf = malloc(sizeof(struct meta_flow));
	
	if(p->ip_dst.s_addr > p->ip_src.s_addr)
	{
		mf->ip1 = p->ip_src.s_addr;
		mf->ip2 = p->ip_dst.s_addr;
		mf->port1 = p->src_port;
		mf->port2 = p->dst_port;
	}
	else
	{
		mf->ip2 = p->ip_src.s_addr;
		mf->ip1 = p->ip_dst.s_addr;
		mf->port2 = p->src_port;
		mf->port1 = p->dst_port;
	}

	mf->hash_key = p->key;

	return mf;
}

/*** ************************************************************************************ ***/

/* Create a new flow from packet
 *
 * @return a pointer to the created flow
 */
flow_t* flow_create(struct meta_flow* meta, packet_t* p)
{
	flow_t* f = malloc(sizeof(flow_t));
	bzero(f, sizeof(flow_t));

	pthread_rwlock_init(&(f->sem), NULL);

	pthread_rwlock_wrlock(&(f->sem));

	f->hash_key = meta->hash_key;
	f->ip1.s_addr = meta->ip1;
	f->ip2.s_addr = meta->ip2;
	f->port1 = meta->port1;
	f->port2 = meta->port2;

	f->start = p->timestamp;
	f->last_update = p->timestamp;
	f->end = 0;

	f->tot_pkt = 1;
	f->tot_byte = p->size;

	pthread_rwlock_unlock(&(f->sem));

	return f;
}

/* Create a new flow from packet
 *
 * @param packet_t*
 *
 * @return a pointer to the created flow
 */
int flow_delete(flow_t* f)
{
	free(f);
	return 1;
}

/* Delete selected flow
 *
 * @param flow_t*
 *
 * @return 1 for success, 0 otherwise
 */
int flow_update(flow_t* f, packet_t* p, struct meta_flow* meta)
{
	pthread_rwlock_rdlock(&(f->sem));

	if(f == NULL)
	{
		sprintf(errflow, "flow pointer is NULL");
		return 0;
	}

	if( (meta->hash_key != f->hash_key) || (meta->ip1 != f->ip1.s_addr) || (meta->ip2 != f->ip2.s_addr)
			|| (meta->port1 != f->port1) || (meta->port2 != f->port2) )
	{
		sprintf(errflow, "flow obsolete");
		return 0;
	}

	pthread_rwlock_unlock(&(f->sem));

	pthread_rwlock_wrlock(&(f->sem));

	f->last_update = p->timestamp;
	f->end = 0;

	f->tot_pkt++;
	f->tot_byte += p->size;

	/* TODO controllo per fine connessione */

	pthread_rwlock_unlock(&(f->sem));

	return 1;
}

/* Update flow from packet
 *
 * @param flow_t*
 * @param packet_t*
 * @param moeta_flow*
 *
 * @return 1 for success, 0 otherwise
 */
int flow_is_expired(flow_t* f)
{
	/*pthread_rwlock_rdlock(&(f->sem));*/

	if(f == NULL)
	{
		/*pthread_rwlock_unlock(&(f->sem));*/
		return 0;
	}

	if( (estimate_time - f->last_update) > FLOW_EXPIRE_TIME )
	{
		/*pthread_rwlock_unlock(&(f->sem));*/
		return 1;
	}
	else
	{
		/*pthread_rwlock_unlock(&(f->sem));*/
		return 0;
	}
}

/* Update flow from packet
 *
 * @param flow_t*
 * @param packet_t*
 * @param moeta_flow*
 *
 * @return 1 for success, 0 otherwise
 */
void flow_update_time(time_t t)
{
	estimate_time = t;
}

/* Update the estimated time to the time of target packet
 *
 * @return the timestamp of the estmated time
 */
time_t flow_estimate_time()
{
	return estimate_time;
}

/* Calculate the hash key for the target packet
 *
 * @param packet_t*
 *
 * @return the hash key for the target packet
 */
u_int flow_hash_key(packet_t* p)
{
	u_long sum = (u_long) p->ip_src.s_addr + p->ip_dst.s_addr + p->src_port + p->dst_port;
	u_int key = (u_int) sum % HASH_SIZE;

	return key;
}

/*** ************************************************************************************ ***/
