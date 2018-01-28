#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "hashtable.h"

/*#define VERBOSE*/

t_hashTable *createHash(int tableSize, unsigned int (*hashfunc)(void *), int (*updatevalue)(void *, void *, int), char *(*printkey)(const void *), char *(*printvalue)(const void *))
{
	int index;
	t_hashTable *tabella;
	if (tableSize <= 0)
	{
		fprintf(stderr,"createHash: dimensione tabella non valida\n");
		return NULL;
	}
	if (hashfunc == NULL)
	{
		fprintf(stderr,"createHash: funzione hash non valida\n");
		return NULL;
	}
	if (updatevalue == NULL)
	{
		fprintf(stderr,"createHash: funzione updatehash non valida\n");
		return NULL;
	}
	tabella = calloc(1,sizeof(t_hashTable));
	if (!tabella)
	{
		fprintf(stderr,"createHash: impossibile allocare memoria\n");
		return NULL;
	}
	tabella->size = tableSize;
	tabella->table = calloc(tableSize,sizeof(t_list_head));
	tabella->hashfunc = hashfunc;
	tabella->updatevalue = updatevalue;
	tabella->printkey = printkey;
	tabella->printvalue = printvalue;
	if (!tabella->table)
	{
		fprintf(stderr,"createHash: impossibile allocare memoria\n");
		free (tabella);
		return NULL;
	}
	for(index = 0; index < tabella->size; index ++)
	{
		int res = pthread_spin_init(&(tabella->table[index].busy),PTHREAD_PROCESS_PRIVATE);
		if(res)
		{
			fprintf(stderr,"createHash: impossibile inizializzare le spinlock\n");
			index--;
			for(; index <= 0; index--)
				pthread_spin_destroy(&(tabella->table[index].busy));
			free(tabella->table);
			free(tabella);
			return NULL;
		}
	}
	return tabella;
}

/*Dealloca la memoria utilizzata dalla tabella*/
void deleteHash(t_hashTable *ht)
{
	int i;
	if (!ht)
	{
		fprintf(stderr,"deleteHash: tabella hash non valida (puntatore a NULL)\n");
		return;
	}
	for (i = 0; i < ht->size; i++)
	{
		t_hashEntry *corrente = ht->table[i].first;
		t_hashEntry *tmp;
		while (corrente)
		{
			tmp = corrente->next;
			deleteHashElement(corrente);
			corrente = tmp;
		}
	}
	free(ht->table);
	free(ht);
}

int hashFunction (const t_pkt_info *key, t_hashTable *ht)
{
	unsigned int hash;
	if (!key || !ht)
	{
		fprintf(stderr,"hashFunction: impossibile calcolare l'hash (puntatori a NULL)\n");
		return -1;
	}
	hash = (*(ht->hashfunc))(key);
	return hash % ht->size;
}

t_hashEntry *updateHashEntry(t_hashTable *ht, const t_pkt_info *key)
{
	int hash;
	t_hashEntry *precedente;
	t_hashEntry *aggiornando;
	t_direction dir;
	if (!ht || !key)
	{
		fprintf(stderr,"updateHashEntry: tabella o chiave non validi (puntatori a NULL)\n");
	}
	hash = hashFunction(key,ht);
	if (hash == -1)
	{
		fprintf(stderr,"updateHashEntry: errore della funzione hash\n");
		return NULL;
	}
	precedente = NULL;
	aggiornando = ht->table[hash].first;
	while (aggiornando && !belongsTo(key,&(aggiornando->key),&dir))
	{
		precedente = aggiornando;
		aggiornando = aggiornando->next;
	}
	if(aggiornando)
	{
		int expired;
		/* Aggiorna il flusso */
		expired = (*(ht->updatevalue))(key,&(aggiornando->value),dir);
#ifdef VERBOSE
		fprintf(stdout,"UPDATED:\n");
		printHashEntry(stdout,ht,aggiornando);
#endif
		/*
		if (expired)
		{//il flusso va rimosso
			if (!precedente)
			{//caso in cui l'elemento da rimuovere viene trovato
			 //in testa alla lista di trabocco

				ht->table[hash].first = aggiornando->next;
				return aggiornando;
			}
			//rimozione dell'elemento trovato
			precedente->next = aggiornando->next;
			printHashEntry(...);
		}
		*/
		return aggiornando;
	}
	/* Creo un nuovo flusso e lo inserisco in testa alla lista di trabocco
#ifdef __FAVOR_BSD
	if(key->ip_p == 6 && !( (key->TCPflags) & TH_SYN) )
	{
		fprintf(stdout,"PACCHETTO SPURIO!!\n");
		return NULL;
	}
#else // !__FAVOR_BSD
	if(key->ip_p == 6 && !key->syn)
	{
		fprintf(stdout,"PACCHETTO SPURIO!!\n");
		return NULL;
	}
#endif // __FAVOR_BSD
	*/
	aggiornando = calloc(1,sizeof(t_hashEntry));
	if (!aggiornando)
	{
		fprintf(stderr,"updateHashEntry: impossibile allocare memoria\n");
		return NULL;
	}
	fillFlow(key,&(aggiornando->key),&(aggiornando->value));
	pthread_spin_lock(&ht->table[hash].busy);
	aggiornando->next = ht->table[hash].first;
	ht->table[hash].first = aggiornando;
	pthread_spin_unlock(&ht->table[hash].busy);
#ifdef VERBOSE
	fprintf(stdout,"ADDED NEW:\n");
	printHashEntry(stdout,ht,aggiornando);
#endif
	return aggiornando;
}

int printHashEntry (FILE * uscita, t_hashTable *ht, t_hashEntry *e)
{
	int x;
	char *key;
	char *value;
	if (!uscita || !e || !ht)
	{
		fprintf(stderr,"printHashEntry: file o elemento o tabella non validi (puntatore a NULL)\n");
		return -1;
	}
	if (ht->printkey)
		key = (*(ht->printkey))(&(e->key));
	else
		key = "UNPRINTABLE";
	if (ht->printvalue)
		value = (*(ht->printvalue))(&(e->value));
	else
		value = "UNPRINTABLE";
	x = fprintf(uscita,"key: %s, value: %s\n",key,value);
	if (x < 0)
	{
		fprintf(stderr,"printHashElement: errore di output\n");
		return -1;
	}
	return x;
}

int printHashTable (FILE *uscita, t_hashTable *t)
{
	int x;
	int index;
	if (!uscita || !t)
	{
		fprintf(stderr,"printHashTable: file o tabella non validi (puntatore a NULL)\n");
		return -1;
	}
	x = fprintf(stdout,"HASH TABLE:\nSIZE: %d\n",t->size);
	for(index = 0; index < t->size; index++)
	{
		t_hashEntry *entry = t->table[index].first;
		fprintf(stdout,"Lista di trabocco n°%d:\n",index);
		while (entry)
		{
			printHashEntry(stdout,t,entry);
			entry = entry->next;
		}
	}
	fprintf(stdout,"+++++++++++\n");
	return x;
}

/*Dealloca la memoria utilizzata da un elemento*/
void deleteHashElement (t_hashEntry *e)
{
	if (!e)
	{
		fprintf(stderr,"deleteHashElement: elemento non valido (puntatore a NULL)\n");
		return;
	}
	free(e);
}
