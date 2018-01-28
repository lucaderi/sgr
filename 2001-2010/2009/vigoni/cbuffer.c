/*
 * cbuffer.c
 *
 *  Created on: 26-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */
#ifndef CAPTURE_H_
#include "capture.h"
#endif

#include "cbuffer.h"

/*** ************************************************************************************* ***/

/* Create an empty cbuffer and allocate memory for that
 *
 * @return a cbuffer struct that describe this circular buffer
 */
struct cbuffer* cbuffer_init()
{
	struct cbuffer* buf = malloc(sizeof(struct cbuffer));

	buf->ins_elem = 0;
	buf->next_elem = 0;
	buf->size = 0;

	return buf;
}

/* Insert a packet in the buffer
 *
 * @param packet_t*
 * @param cbuffer*
 *
 * @return -1 if cannot insert the packet 'p' in the buffer
 * @return 1 for success
 */
int cbuffer_put(packet_t* p, struct cbuffer* cbuf)
{
	if(cbuf->size >= BUF_SIZE)
		return -1;

	cbuf->buf[cbuf->ins_elem] = p;

	/* control variable */
	if(cbuf->ins_elem < BUF_SIZE-1)
		cbuf->ins_elem++;
	else
		cbuf->ins_elem = 0;

	cbuf->size++;

	/*printf("cbuffer_put: size = %d\n", cbuf->size);*/

	return 1;
}

/* Get the next packet from the cbuffer b
 *
 * @param cbuffer*
 *
 * @return a pointer to the next packet_t in the cbuffer (FIFO)
 */
packet_t* cbuffer_get_next(struct cbuffer* b)
{
	packet_t* p = NULL;

	/*printf("cbuffer_get_next: size = %d\n", b->size);*/

	if(b->size == 0)
		return NULL;

	p = b->buf[b->next_elem];

	if(b->next_elem < BUF_SIZE-1)
	{
		if(b->ins_elem != b->next_elem-1)
			b->next_elem++;
	}
	else
	{
		if(b->ins_elem > 0)
			b->next_elem = 0;
	}

	b->size--;
	/*printf("cbuffer_put: size = %d (packet extracted)\n", b->size);
	printf("cbuffer_put: packet extracted [SEQ=%d]\n", p->seq_num);*/
	return p;
}

/*** ************************************************************************************* ***/
