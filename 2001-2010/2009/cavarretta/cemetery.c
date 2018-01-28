#include "cemetery.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

t_cemetery *createCemetery()
{
	t_cemetery *cemetery;
	cemetery = calloc(1,sizeof(t_cemetery));
	if (!cemetery)
	{
		fprintf(stderr,"createCemetery: Impossibile allocare memoria.\n");
		return NULL;
	}
	cemetery->fibN = FIRST + SECOND;
	cemetery->fibNminus1 = SECOND;
	cemetery->first = calloc(cemetery->fibN + 1,sizeof(t_hashEntry *));
	if (!cemetery->first)
	{
		fprintf(stderr,"createCemetery: Impossibile allocare memoria.\n");
		free(cemetery);
		return NULL;
	}
	cemetery->lastNotEmpty = cemetery->first;
	cemetery->last = 0;
	cemetery->lastNotEmptyLen = FIRST + SECOND;
	cemetery->prevBlockLen = SECOND;
	return cemetery;
}

void addToCemetery(t_cemetery *cemetery, const t_hashEntry *entry)
{
	if(cemetery->last == cemetery->lastNotEmptyLen)
	{
		unsigned int tmp;
		if(!cemetery->lastNotEmpty[cemetery->last])
		{
			tmp = cemetery->fibN;
			cemetery->fibN += cemetery->fibNminus1;
			cemetery->fibNminus1 = tmp;
			cemetery->lastNotEmpty[cemetery->last] = calloc(cemetery->fibN + 1,sizeof(t_hashEntry *));
			if(!cemetery->lastNotEmpty[cemetery->last])
			{
				fprintf(stderr,"addToCemetery: impossibile allocare memoria\n");
				exit(-1);
			}
		}
		cemetery->lastNotEmpty = (t_hashEntry **)cemetery->lastNotEmpty[cemetery->last];
		cemetery->last = 0;
		cemetery->lastNotEmpty[(cemetery->last)++] = entry;
		tmp = cemetery->lastNotEmptyLen;
		cemetery->lastNotEmptyLen += cemetery->prevBlockLen;
		cemetery->prevBlockLen = tmp;
	}
	else
	{
		cemetery->lastNotEmpty[(cemetery->last)++] = entry;
	}
}

unsigned int freeCemetery(t_cemetery *cemetery)
{
	unsigned int freed = 0;
	unsigned int fibN = FIRST + SECOND;
	unsigned int predFibN = SECOND;
	t_hashEntry **current = cemetery->first;
	unsigned int pos = 0;
	while(*current)
	{
		if(pos == fibN)
		{
			unsigned int tmp = fibN;
			current = (t_hashEntry **)(*current);
			fibN += predFibN;
			predFibN = tmp;
			pos = 0;
		}
		free(*current);
		*current = NULL;
		freed++;
		current++;
		pos++;
	}
	cemetery->lastNotEmpty = cemetery->first;
	cemetery->last = 0;
	cemetery->lastNotEmptyLen = FIRST + SECOND;
	cemetery->prevBlockLen = SECOND;
	return freed;
}
