#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rrd.h>
#include "timer.h"
#include "sniffer.h"

struct timeval tvRRD = {5,0};
struct timeval tvUndertaker = {60,0};
struct event evRRD;
struct event evUndertaker;

char *command[CMD_NO];

t_cemetery *cemetery;
extern t_hashTable *flowsTable;

extern unsigned int inbound;
extern unsigned int outbound;
extern unsigned int promisquous;

void rrd_updater(int fd, short event, void *ud)
{
	int result;
	char vals[VAL_LEN];
    evtimer_add(&evRRD, &tvRRD);
    snprintf(vals,VAL_LEN,"N:%d:%d:%d",inbound,outbound,promisquous);
    command[2] = vals;
    result = rrd_update(CMD_NO,command);
    if (result)
    {
    	fprintf(stderr,"ERROR: rrd_update, %s\n",rrd_get_error());
    	/*exit(-1);*/
    }
}

/* prints flows on standard output */
void exportFlow(t_flow_ID *flowID, t_flow_info *flowInfo)
{
	char fstaddr[IP_STR_LEN];
	char begin[80];
	char last[80];
	struct tm *ts = localtime(&flowInfo->begin);
	strcpy(fstaddr,getFstIP(flowID));
	strftime(begin, sizeof(begin), "%a %Y-%m-%d %H:%M:%S %Z", ts);
	ts = localtime(&flowInfo->last);
	strftime(last, sizeof(last), "%a %Y-%m-%d %H:%M:%S %Z", ts);
	fprintf(stdout,"\nBegin: %s\tLast received: %s\nProto: %u\t%s:%u<->%s:%u\tpackets->: %u, bytes->: %u, packets<-: %u, bytes<-: %u\n",
			begin,
			last,
			flowID->ip_protocol,
			fstaddr,getFstPort(flowID),
			getSndIP(flowID),getSndPort(flowID),
			flowInfo->fstTOsnd_pkts_NO, flowInfo->fstTOsnd_bytes,
			flowInfo->sndTOfst_pkts_NO, flowInfo->sndTOfst_bytes);
}

/* collects expired flows from the flow cache and puts them into the "cemetery"
 * a data structure needed to perform delayed frees securely */
void undertaker(int fd, short event, void *ud)
{
	unsigned int freed;
	unsigned int index;
	unsigned int totalflows = 0;
	unsigned int removedflows = 0;
	time_t currentTime;
	t_hashEntry *previous;
	t_hashEntry *current;
	evtimer_add(&evUndertaker, &tvUndertaker);
	currentTime = time(NULL);
	freed = freeCemetery(cemetery);
#ifdef PRINT_EXPORTED_FLOWS
	fprintf(stdout,"undertaker: The following flows were exported:\n");
#endif
	for(index = 0; index < flowsTable->size; index++)
	{
		unsigned int listcount = 0;
		previous = NULL;
		current = flowsTable->table[index].first;
		while (current)
		{
			listcount++;
			if((currentTime - current->value.begin) > MAX_FLOW_DURATION || (currentTime - current->value.last) > MAX_FLOW_INACTIVITY)
			{
				/* devo rimuovere la testa della lista */
				if(previous == NULL)
				{
					pthread_spin_lock(&flowsTable->table[index].busy);
					if(flowsTable->table[index].first != current)
					{
						pthread_spin_unlock(&flowsTable->table[index].busy);
						previous = NULL;
						current = flowsTable->table[index].first;
						listcount = 0;
						continue;
					}
					else
					{
						flowsTable->table[index].first = current->next;
						previous = NULL;
						pthread_spin_unlock(&flowsTable->table[index].busy);
						removedflows++;
						addToCemetery(cemetery,current);
#ifdef PRINT_EXPORTED_FLOWS
						/*printHashEntry(stdout,flowsTable,current);*/
						exportFlow(&current->key,&current->value);
#endif
						current = current->next;
						continue;
					}
				}
				/* devo rimuovere da una posizione qualsiasi */
				else
				{
					previous->next = current->next;
					removedflows++;
					addToCemetery(cemetery,current);
#ifdef PRINT_EXPORTED_FLOWS
					/*printHashEntry(stdout,flowsTable,current);*/
					exportFlow(&current->key,&current->value);
#endif
					current = current->next;
					continue;
				}
			}
			previous = current;
			current = current->next;
		}
		totalflows += listcount;
	}
}

/* the thread that regularly calls the functions that update RRD and clean the flow cache */
void *timer(void *arg)
{
	command[0] = "update";
	command[1] = "rrd.rrd";
	cemetery = createCemetery();
    event_init();
    if(arg)
    {
    	evtimer_set(&evRRD, rrd_updater, NULL);
    	evtimer_add(&evRRD, &tvRRD);
    }
    evtimer_set(&evUndertaker, undertaker, NULL);
    evtimer_add(&evUndertaker, &tvUndertaker);
    event_dispatch();
    return (void *)NULL;
}
