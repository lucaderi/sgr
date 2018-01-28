/*
 * hashtable.c
 *
 *  Created on: 31-mag-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#include "hashtable.h"

/*** ********************************************************************************************* ***/

/* Create an empty HASHTABLE by size
 *
 * @param u_int the size of the table
 *
 * @return a pointer to the created HASHTABLE
 */
HASHTABLE* hashtable_init(const u_int size)
{
	HASHTABLE* ht = malloc(sizeof(HASHTABLE));		/* memory allocation for information */
	HASH_HEAD* nodes = NULL;
	int i = 0;

	ht->size = 0;
	ht->set_size = size;
	/*ht->nodes = calloc(size, sizeof(HASH_NODE));	 memory allocation for data */
	ht->heads = calloc(size, sizeof(HASH_HEAD));

	for(i=0; i<size; i++)
	{
		ht->heads[i].line_nodes = NULL;
		pthread_rwlock_init(&(ht->heads[i].sem), NULL);
	}

	return ht;
}

/* Insert a node in the hashtable
 *
 * @param HASHTABLE*	a pointer to the table
 * @param flow_t		a pointer to the flow
 *
 * @return 1 for success, 0 otherwise
 */
int hashtable_insert_node(HASHTABLE* hashtable, flow_t* flw)
{
	HASH_NODE* new_node = malloc(sizeof(HASH_NODE));	/* new node memory allocation */
	/*HASH_NODE* aux = hashtable->nodes[flw->hash_key];	 aux node start from the 'flw->hash_key' position in the table */
	HASH_HEAD* head = &hashtable->heads[flw->hash_key];

	new_node->f = flw;

	new_node->prev = NULL;
	new_node->next = head->line_nodes;

	pthread_rwlock_trywrlock(&(head->sem));

	if(head->line_nodes != NULL)
		head->line_nodes->prev = new_node;
	hashtable->heads[flw->hash_key].line_nodes = new_node;

	pthread_rwlock_unlock(&(head->sem));

	hashtable->size++;

	return 1;
}

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
		u_short port1, u_short port2)
{
	HASH_HEAD* n = &hashtable->heads[key];
	HASH_NODE* aux;
	flow_t* f;

	pthread_rwlock_tryrdlock(&(n->sem));

	if(n->line_nodes == NULL)
		return NULL;

	aux = n->line_nodes;

	while( aux != NULL )
	{
		f = aux->f;

		/*pthread_rwlock_rdlock(&(f->sem));*/

		if( (ip1 ==  f->ip1.s_addr) && (ip2 =  f->ip2.s_addr) )
		{
			if( (port1 == f->port1) && (port2 == f->port2) )
			{
				/*pthread_rwlock_unlock(&(f->sem));*/
				return aux;
			}
		}
		aux = aux->next;

		/*pthread_rwlock_unlock(&(f->sem));*/
	}

	pthread_rwlock_unlock(&(n->sem));

	return NULL;
}

/* Search for a node in the hashtable
 *
 * @param HASHTABLE*		a pointer to the table
 * @param struct meta_flow*	a pointer to the meta information
 *
 * @return a pointer to the selected node, NULL if node can't be found
 */
HASH_NODE* hashtable_get_node_from_meta(HASHTABLE* hashtable, struct meta_flow* meta)
{
	HASH_NODE* n = NULL;

	n = hashtable_get_node(hashtable, meta->hash_key, meta->ip1, meta->ip2, meta->port1, meta->port2);
	return n;
}

/* Kill a node in the hashtable (insert it in the 'dead queue')
 *
 * @param HASHTABLE*		a pointer to the table
 * @param struct dead_node*	a pointer to the 'dead queue'
 * @param HASH_NODE*		the node to kill
 *
 * @return 1 for success, 0 otherwise
 */
struct dead_node* hashtable_kill_node(HASHTABLE* hashtable, struct dead_node* dead_queue,
		HASH_NODE* n)
{
	struct dead_node *dn, *last;
	/*struct hash_node *prev, *next;*/

	if(dead_queue == NULL)
		printf("     hashtable_kill_node: dead_queue is empty\n");

	if(n->prev != NULL) n->prev->next = n->next;
	else
	{
		/*pthread_rwlock_trywrlock(&(hashtable->heads[n->f->hash_key].sem));*/
		hashtable->heads[n->f->hash_key].line_nodes = n->next;
		/*pthread_rwlock_unlock(&(hashtable->heads[n->f->hash_key].sem));*/
	}

	if(n->next != NULL) n->next->prev = n->prev;

	dn = calloc(1, sizeof(struct dead_node));
	last = dead_queue;

	dn->node = n;

	/*if(prev != NULL) prev->next = next;
	if(next != NULL) next->prev = prev;*/

	dn->prev = NULL;
	dn->next = dead_queue;
	if(last != NULL)
		last->prev = dn;

	hashtable->size--;

	n->next = n->prev;
	/*usleep(100000);*/
	n->next = NULL;

	return dn;
}

/* Dealete (and deallocate) the next node in the dead queue, execute also the pop callback
 * for processing the extracted node
 *
 * @param struct dead_node*	a pointer to the 'dead queue'
 * @param struct dead_node*	a pointer to the node to delete in the 'dead queue'
 * @param dead_pop_callback	the callback
 *
 * @return a pointer to the next node in the dead_queue (FIFO), NULL if the queue is empty
 */
struct dead_node* hashtable_dead_pop(struct dead_node* dead_queue, struct dead_node* next,
		dead_pop_callback callback)
{
	struct dead_node* last;
	struct dead_node* top;
	flow_t* f;
	HASH_NODE* node;

	if(dead_queue == NULL)
	{
		printf("     hashtable_dead_pop: dead_queue is empty\n");
		return NULL;
	}

	if(next == NULL)
	{
		top = dead_queue;
		while(top->next != NULL)
		{
			/* printf("{flow_id: %d}", top->node->f->flow_id); */
			top = top->next;
		}
		/* printf("\n"); */
	}
	else
		top = next;

	last = top->prev;
	if(last != NULL) last->next = NULL;

	if(top != NULL)
	{
		node = top->node;
		f = node->f;
	}
	else return NULL;

	printf("     hashtable_dead_pop: dead_pop flow [key: %d, flow_id: %d]\n", f->hash_key, f->flow_id);

	if(callback != NULL) callback(f);

	free(f);
	free(node);
	free(top);

	return last;
}

/*** ********************************************************************************************* ***/
