/*
 * cbuffer.h
 *
 *  Created on: 30-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#ifndef CBUFFER_H_
#define CBUFFER_H_

#include "capture.h"

#define BUF_SIZE 1024 /* 1024 packets on buffers */

struct cbuffer
{
	u_int size;					/* buffer size (in elem) */
	u_int next_elem;			/* the index of the next elem to read */
	u_int ins_elem;				/* the index of the first free position in buffer */
	packet_t* buf[BUF_SIZE];	/* base address for buffer */
};

/* Create an empty cbuffer and allocate memory for that
 *
 * @return a cbuffer struct that describe this circular buffer
 */
struct cbuffer* cbuffer_init();

/* Insert a packet in the buffer
 *
 * @param packet_t*
 * @param cbuffer*
 *
 * @return -1 if cannot insert the packet 'p' in the buffer
 * @return 1 for success
 */
int cbuffer_put(packet_t* p, struct cbuffer* cbuf);

/* Get the next packet from the cbuffer b
 *
 *@param cbuffer*
 *
 * @return a pointer to the next packet_t in the cbuffer (FIFO)
 */
packet_t* cbuffer_get_next(struct cbuffer* b);

#endif /* CBUFFER_H_ */
