/* *******************************************
Global def for all file

********************************************* */

#ifndef __GLOBAL_CODE_H__
#define __GLOBAL_CODE_H__ 001

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>

#include <net/ethernet.h> /* the L2 protocols */

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h> /* includo libreria per tcp */

#include <proc/readproc.h>
#include <pcap/pcap.h>

typedef struct data
{
	unsigned int byteS;
	unsigned int byteR;
	unsigned int pktS;
	unsigned int pktR;
} data_t;

typedef struct process
{
	int PID;
	int active;
	char name[512];
	char path[PATH_MAX];
	char user[512];
	data_t info;
} process_t;

#include "arrQueue.h"
#include "intQueue.h"
#include "int_list.h"
#include "network_monitoring.h"
#include "mycmacro.h"
#include "ThScan.h"
#include "ThDemon.h"
#include "ThPut.h"

/**************************************************************************/
//msg  debug on/off
//#define DEBUG_BLOCK_ON

//if !debug  enable output print
#ifndef DEBUG_BLOCK_ON
#define INTERFACE_TH_ENABLE_PRINT
#endif

/**************************************************************************/

extern int verbose;
extern unsigned char request_terminate_process;

pcap_t *pd;
process_t *process_list;

int pid_max;
char *device;
char *myIp;
FILE *fp;
unsigned int contUnricognizable;
unsigned int contPktRx;
unsigned int pktFullPcap;

queueA_t queueMiss;
queueA_t queuePkt;
queueI_t queueDead;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

/*private exit code*/
#define ERRINPUTPARAM 1	/*input parameter error*/
#define ERRINPUTDATA 2	 /*input value error    */
#define ERRFUNCINPUTDATA 3 /*generic func input data error    */
#define ERRORFILE 4		   /*generic error file */
#define ERRORMEMORY 5	  /*generic error file */
#define ERRDEVICE 6		   /*device not found*/

/**************************************************************************/

#endif

/* OTTENERE INFO PROCESSI

Sito ufficiale: http://procps.sourceforge.net/index.html
Info ed esempi: http://codingrelic.geekhold.com/2011/02/listing-processes-with-libproc.html

Per info su come ottenere e scorrere lista processi:
man openproc
man readproc

Per info sulla struttura dati restituita per ciascun processo:
vi /usr/include/proc/readproc.h

In caso di problemi durante il make, cercare tra i pacchetti disponibili libprocps
e installare sia la libreria che la versione -dev
*/
