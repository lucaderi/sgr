/*
 * hashtable.h
 *
 *  Created on: 30-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#ifndef HASHTABLE_H_
#define HASHTABLE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flow.h"

#define DEFAULT_HASH_SIZE 100

/* Node */
typedef struct hash_node
{
	flow_t* f;
	struct hash_node* prev;
	struct hash_node* next;
} HASH_NODE;

/* Head */
typedef struct head_hash_node
{
	struct hash_node* line_nodes;
	pthread_rwlock_t sem;
} HASH_HEAD;

/* Deleted Node */
struct dead_node
{
	struct hash_node* node;
	struct dead_node* next;
	struct dead_node* prev;
};

/* Table */
typedef struct hashtable
{
	size_t size;
	size_t set_size;
	/*struct hash_node** nodes;*/
	struct head_hash_node* heads;
} HASHTABLE;

/* Callback for processing deleted node in the hashtable
 *
 */
typedef void (*dead_pop_callback)(flow_t* f);

/*** ********************************************************************************************* ***/

/* Create an empty HASHTABLE by size
 *
 * @param u_int the size of the table
 *
 * @return a pointer to the created HASHTABLE
 */
HASHTABLE* hashtable_init(const u_int size);

/* Search for a node in the hashtable
 *
 * @param HASHTABLE*	a pointer to the table
 * @param u_int			the key of the node to get
 * @param in_addr_t		the ip address n.1
 * @param in_addr_t		the ip address n.2
 * @param u_short		the port number n.1
 * @param u_short		the port number n.2
 *
 * @return a pointer to the selected node, NULL if node can't be found
 */
HASH_NODE* hashtable_get_node(HASHTABLE* hashtable, u_int key,
		in_addr_t ip1, in_addr_t ip2,
		u_short port1, u_short port2);

/* Search for a node in the hashtable
 *
 * @param HASHTABLE*		a pointer to the table
 * @param struct meta_flow*	a pointer to the meta information
 *
 * @return a pointer to the selected node, NULL if node can't be found
 */
HASH_NODE* hashtable_get_node_from_meta(HASHTABLE* hashtable, struct meta_flow* meta);

/* Insert a node in the hashtable
 *
 * @param HASHTABLE*	a pointer to the table
 * @param flow_t		a pointer to the flow
 *
 * @return 1 for success, 0 otherwise
 */
int hashtable_insert_node(HASHTABLE* hashtable, flow_t* flw);

/* Kill a node in the hashtable and insert it in the dead_queue
 *
 * @param HASHTABLE*		a pointer to the table
 * @param struct dead_node*	a pointer to the 'dead queue'
 * @param HASH_NODE*		the node to kill
 *
 * @return 1 for success, 0 otherwise
 */
struct dead_node* hashtable_kill_node(HASHTABLE* hashtable, struct dead_node* dead_queue, HASH_NODE* n);

/* Delete (and deallocate) the next node in the dead queue, execute also the pop callback
 * for processing the extracted node
 *
 * @param struct dead_node*	a pointer to the 'dead queue'
 * @param struct dead_node*	a pointer to the node to delete in the 'dead queue'
 * @param dead_pop_callback	the callback
 *
 * @return a pointer to the next node in the dead_queue (FIFO), NULL if the queue is empty
 */
struct dead_node* hashtable_dead_pop(struct dead_node* dead_queue, struct dead_node* next,
		dead_pop_callback callback);

/*** ********************************************************************************************* ***/

#endif /* HASHTABLE_H_ */
