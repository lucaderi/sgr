/*
 * hashtbl.c
 *      Author: Giovanni Avveduto
 *      SGR Exercise
 */

#include"hashtbl.h"

#include<string.h>
#include<stdio.h>
#include <time.h>

/*create hashtable of specified size*/
HASHTBL *hashtbl_create(hash_size size) {
	HASHTBL *hashtbl;

	if (!(hashtbl = calloc(1,sizeof(HASHTBL))))
		return NULL;

	if (!(hashtbl->nodes = calloc(size, sizeof(struct hashnode_s*)))) {
		free(hashtbl);
		return NULL;
	}

	hashtbl->size = size;
	return hashtbl;
}

/*free hashtable*/
void hashtbl_destroy(HASHTBL *hashtbl) {
	int n;
	struct hashnode_s *node, *oldnode;

	for (n = 0; n < hashtbl->size; n++) {
		node = hashtbl->nodes[n];
		while (node) {
			free(node->data);
			oldnode = node;
			node = node->next;
			free(oldnode);
		}
	}
	free(hashtbl->nodes);
	free(hashtbl);
}

int hashtbl_insert(HASHTBL *hashtbl, struct queue_elem *data) {
	struct hashnode_s *node;
	int h = hash(data) % hashtbl->size;
	node = hashtbl->nodes[h];
	while (node) {

		/*if exist flow on same direction*/
		if (((node->data->ip_src == data->ip_src) && (node->data->ip_dst
				== data->ip_dst) && (node->data->port_src == data->port_src)
				&& (node->data->port_dst == data->port_dst) && (node->data->type
				== data->type))) {

			node->data->pkt_in++;
			node->data->byte_in += data->byte_len;
			node->data->last_time=data->timestamp;

			/*return flow updated*/
			return 1;

		}
		/*if exists on other direction*/
		else if ((node->data->ip_src == data->ip_dst) && (node->data->ip_dst
				== data->ip_src) && (node->data->port_src == data->port_dst)
				&& (node->data->port_dst == data->port_src) && (node->data->type
				== data->type)) {

			node->data->pkt_out++;
			node->data->byte_out += data->byte_len;
			node->data->last_time= data->timestamp;

			/*return flow updated*/
			return 1;
		}
		node = node->next;
	}
	if (!(node = calloc(1,sizeof(struct hashnode_s))))
		/*error: failed insert*/
		return -1;

	struct flow_bidir *fl = calloc(1, sizeof(struct flow_bidir));
	if (!fl) return -1;
	fl->ip_src=data->ip_src;
	fl->ip_dst=data->ip_dst;
	fl->port_src=data->port_src;
	fl->port_dst=data->port_dst;
	fl->type=data->type;
	fl->start_time=data->timestamp;
	fl->last_time=data->timestamp;
	fl->pkt_in = 1;
	fl->pkt_out = 0;
	fl->byte_in = data->byte_len;
	node->data = fl;
	node->next = hashtbl->nodes[h];
	hashtbl->nodes[h] = node;

	/*return new flow created*/
	return 0;
}

/*return list of expired flows*/
struct dead_hashnode *hashtbl_remove(HASHTBL *hashtbl, int flow_lifetime,int flow_timeout, struct dead_hashnode **exp_flows) {
	struct hashnode_s *node, *prevnode = NULL;

	int i;
	for (i=0;i<hashtbl->size;i++){
		node=hashtbl->nodes[i];
		prevnode=NULL;
		uint32_t now=(uint32_t) time(NULL);
		while(node){
			if (((node->data->last_time-node->data->start_time)>=flow_lifetime)||
					((now - node->data->last_time)>= flow_timeout)){
				if (prevnode) prevnode->next=node->next;
				else hashtbl->nodes[i]=node->next;

				struct dead_hashnode *dead=calloc(1,sizeof(struct dead_hashnode));
				dead->node=node;
				dead->next=*exp_flows;
				*exp_flows=dead;
				node=node->next;
			}
			else
			{
				prevnode=node;
				node=node->next;
			}
		}
	}
	return *exp_flows;
}
