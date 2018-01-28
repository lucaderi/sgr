#include "utils.h"
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>

/* HASH TABLE WILL BE 2^HASHHIGHBIT SIZED*/
#define HASHHIGHBIT 20
#define HASHSIZE (1 << HASHHIGHBIT)
#define HASHMASK (HASHSIZE - 1)

#define QUEUE_NO_HIGHBIT 2
#define QUEUE_NO (1 << QUEUE_NO_HIGHBIT) 
#define QUEUE_SIZE 16384

/* Delayed free list size */
#define FREE_LIST_SIZE 8192
/* Interval for full flow scanning */
#define FLOW_COLLECTOR_INTERVAL 60

/* Time needed to consider a flow expired */
#define FLOW_EXPIRE_TIME 15
/* Maximum duration for a flow */
#define FLOW_MAX_TIME 1800

typedef u_int hash_t;

/* Packet decoded structure for flow analisys (IPv4 ONLY!)*/
typedef struct packet_decoded 
{
	struct timeval time;
	u_short size;
	u_char proto;
	struct in_addr src, dst;
	u_short src_port, dst_port;
	hash_t hash;
} pkt_t;

/* Entry of the flow table */
typedef struct hash_entry
{
	/* Pointer to next entry */
	struct hash_entry *next;
	/* Key */
	u_long addr1, addr2;
	u_short port1, port2;
	u_char proto;
	/* Value */
	u_long bytes1;
	u_long pkts1;
	u_long bytes2;
	u_long pkts2;
	struct timeval start_time;
	struct timeval last_time;
} flow_t;

/* Element of the flow table */
typedef struct table_element
{
	flow_t *first;
	spinlock_t lock;
} table_element_t;

/* Queue for packets passing */
typedef struct queue
{
	sig_atomic_t first;
	sig_atomic_t last;
	pkt_t q[QUEUE_SIZE];
} queue_t;

/* Calculate hash */
hash_t hash(const pkt_t* pkt);

/* Returns a pointer to a newly created flow table*/
table_element_t * create_flow_table();

/* Match type for flow-pkt */
typedef enum matches {
	NO_MATCH = 0,
	DIR1 = 1,
	DIR2 = 2
} match_t;

/* Compare the keys */
match_t match(pkt_t* pkt, flow_t* entry);

typedef struct flow_processor_args
{
	table_element_t *table;
	queue_t *q;
} flow_processor_args_t;

/* Loops for enqueued packets and aggregates them into flows */
void* flow_processor(void* args);

/* Clean up flow table */
void* flow_collector(void* args);

/* Packet processor for flow management */
int flow_process_pkt(pkt_t* pkt, table_element_t* table,  flow_t **entry);

/* Initialize a packet queue */
void init_queue(queue_t* q);

/* Enqueue a packet */
void enqueue(queue_t* q, pkt_t* p);

/* Dequeue a packet. If queue is empty returns NULL */
pkt_t* dequeue(queue_t* q);
