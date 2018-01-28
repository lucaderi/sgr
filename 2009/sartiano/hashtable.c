#include "hashtable.h"

struct hashtable* create_hashtable() {
	struct hashtable *h;

	h = (struct hashtable*) malloc(sizeof(struct hashtable));
	if (h == NULL)
		return NULL;
	h->table = (struct entry**) calloc(INIT_SIZE, sizeof(struct entry*));
	if (h->table == NULL)
		return NULL;
	h->size = INIT_SIZE;
	h->number_entry = 0;
	return h;
}

unsigned int hashtable_hash(flow_key *k) {
	unsigned int key = 0;

	key += k->ip_src;
	key += k->ip_dst;
	key += k->port_src;
	key += k->port_dst;

	/* Robert Jenkins' 32 bit Mix Function */
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);

	/* Knuth's Multiplicative Method */
	key = (key >> 3) * 2654435761u;

	return key;
}

struct entry* hashtable_search(struct hashtable *h, int hash_result, flow *f) {
	struct entry *e = NULL;

	e = h->table[hash_result];

	while (e != NULL) {
		if (1 == flow_cmp(e->f, f)) {
			return e;
		}
		e = e->next;
	}
	return NULL;
}

void hashtable_delete(struct hashtable *h) {
	int i;
	struct entry *e = NULL;
	for (i = 0; i < INIT_SIZE; i++) {
		e = h->table[i];
		while (e != NULL) {
			h->table[i] = h->table[i]->next;
			free(e->f->key);
			free(e->f);
			free(e);
			e = h->table[i];
		}
	}
	free(h);
}

struct hashtable* hashtable_insert(struct hashtable *h, flow *f,
		pthread_mutex_t* mutex) {
	struct entry *e = NULL;
	int index = hashtable_hash(f->key) % INIT_SIZE;
	e = hashtable_search(h, index ,f);
	if(e == NULL) {
		pthread_mutex_lock(mutex);
		//se non c'è
		e = (struct entry*) malloc (sizeof(struct entry));
		if(e == NULL)
			return NULL;
		e->f = (flow*)malloc(sizeof(flow));
		e->f->key = (flow_key*)malloc(sizeof(flow_key));
		e->f->key->ip_src = f->key->ip_src;
		e->f->key->ip_dst = f->key->ip_dst;
		e->f->key->port_src = f->key->port_src;
		e->f->key->port_dst = f->key->port_dst;
		e->f->first = f->first;
		e->f->last = f->last;
		e->f->length = f->length;
		e->f->pkts = f->pkts;

		//se è il primo elemento
		if(h->table[index] == NULL) {
			e->next = NULL;
			h->table[index] = e;
		} else {
			//altrimenti inserisco in testa
			e->next = h->table[index];
			h->table[index] = e;
		}
		h->number_entry++;
		pthread_mutex_unlock(mutex);
	} else {
		e->f->last = f->last;
		e->f->pkts++;
		e->f->length += f->length;
	}
	return h;
}

