#ifndef ENTRY_H_
#define ENTRY_H_

#include "pkt_info.h"

#define IP_STR_LEN 16
#define FLOW_ID_LEN 79
#define FLOW_INFO_LEN 107

typedef enum Directions
{
	fstTOsnd = 1,
	sndTOfst = -1
} t_direction;

/* a bidirectional flow header */
typedef struct flow_ID
{
	unsigned int first_IP;
	unsigned int second_IP;
	unsigned short int first_port;
	unsigned short int second_port;
	u_char ip_protocol;
} t_flow_ID;

/* Returns 0 if pkt isn't a packet of the flow represented by flow, 1 otherwise
 * and sets dir to inform which unidirectional flow the packet belongs to */
int belongsTo(const t_pkt_info *pkt, const t_flow_ID *flow, t_direction *dir);
char *getFstIP(const t_flow_ID *flowID);
char *getSndIP(const t_flow_ID *flowID);
int getFstPort(const t_flow_ID *flowID);
int getSndPort(const t_flow_ID *flowID);
u_char getFlowProtocol(t_flow_ID *flowID, char *protocol);
char *printFlowID(const t_flow_ID *flowID);

/* a bidirectional flow info */
typedef struct flow_info
{
	time_t begin;
	time_t last;
	unsigned int fstTOsnd_pkts_NO;
	unsigned int sndTOfst_pkts_NO;
	unsigned int fstTOsnd_bytes;
	unsigned int sndTOfst_bytes;
} t_flow_info;

/* updates the unidirectional flow infos according to dir and pkt
 * shall return (it doesn't) if the flow is over (due to TCP connection
 * termination) */
int updateFlow(const t_pkt_info *pkt, t_flow_info *flow, t_direction dir);
char *printFlowInfo(const t_flow_info *flowInfo);
/* used to inizialize a flow with infos holded in it's first packet */
void fillFlow(const t_pkt_info *pkt, t_flow_ID *flowID, t_flow_info *flowInfo);

#endif /*ENTRY_H_*/
