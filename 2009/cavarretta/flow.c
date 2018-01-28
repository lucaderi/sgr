#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int belongsTo(const t_pkt_info *pkt, const t_flow_ID *flow, t_direction *dir)
{
	int belongs = 0;
	if (pkt->ip_p == flow->ip_protocol)
	{
		if (pkt->src_addr.s_addr == flow->first_IP)
		{
			if (pkt->dst_addr.s_addr == flow->second_IP && pkt->src_port == flow->first_port && pkt->dst_port == flow->second_port)
			{
				belongs = 1;
				*dir = fstTOsnd;
			}
		}
		else
			if (pkt->src_addr.s_addr == flow->second_IP)
				if (pkt->dst_addr.s_addr == flow->first_IP && pkt->src_port == flow->second_port && pkt->dst_port == flow->first_port)
				{
					belongs = 1;
					*dir = sndTOfst;
				}
	}
	return belongs;
}

char *getFstIP(const t_flow_ID *flowID)
{
	struct in_addr addr;
	addr.s_addr = flowID->first_IP;
	return inet_ntoa(addr);
}

char *getSndIP(const t_flow_ID *flowID)
{
	struct in_addr addr;
	addr.s_addr = flowID->second_IP;
	return inet_ntoa(addr);
}

int getFstPort(const t_flow_ID *flowID)
{
	return ntohs(flowID->first_port);
}

int getSndPort(const t_flow_ID *flowID)
{
	return ntohs(flowID->second_port);
}

u_char getFlowProtocol(t_flow_ID *flowID, char *protocol)
{
	return flowID->ip_protocol;
}

char *printFlowID(const t_flow_ID *flowID)
{
	char fstaddr[IP_STR_LEN];
	char sndaddr[IP_STR_LEN];
	char *s = malloc(FLOW_ID_LEN * sizeof(char));
	strcpy(fstaddr,getFstIP(flowID));
	strcpy(sndaddr,getSndIP(flowID));
	snprintf(s,FLOW_ID_LEN,"FIRST: %s:%u SECOND: %s:%u PROTOCOL: %u",fstaddr,getFstPort(flowID),sndaddr,getSndPort(flowID),getFlowProtocol(flowID,NULL));
	return s;
}

int updateFlow(const t_pkt_info *pkt, t_flow_info *flow, t_direction dir)
{
	int ret = 0;
	flow->last = pkt->capture_time;
	switch (dir)
	{
	case fstTOsnd:
		flow->fstTOsnd_pkts_NO++;
		flow->fstTOsnd_bytes += pkt->len;
		break;
	case sndTOfst:
		flow->sndTOfst_pkts_NO++;
		flow->sndTOfst_bytes += pkt->len;
	}
	/* Se è un flusso TCP controllo che non sia concluso
# ifdef __FAVOR_BSD
	if (pkt->ip_p == 6 && ( (pkt->TCPflags)&TH_FIN || (pkt->TCPflags)&TH_RST )
	{
		fprintf(stdout,"FLUSSO TCP CHIUSO.\n");
		ret = 1;
	}
# else /* !__FAVOR_BSD
	if (pkt->ip_p == 6 && ( pkt->fin || pkt->rst ))
	{
		fprintf(stdout,"FLUSSO TCP CHIUSO.\n");
		ret = 1;
	}
# endif /* __FAVOR_BSD */
	return ret;
}

char *printFlowInfo(const t_flow_info *flowInfo)
{
	char *s = malloc(FLOW_INFO_LEN * sizeof(char));
	snprintf(s,FLOW_INFO_LEN,"FIRST to SECOND packets: %u bytes: %u SECOND to FIRST packets: %u bytes: %u",flowInfo->fstTOsnd_pkts_NO,flowInfo->fstTOsnd_bytes,flowInfo->sndTOfst_pkts_NO,flowInfo->sndTOfst_bytes);
	return s;
}

void fillFlow(const t_pkt_info *pkt, t_flow_ID *flowID, t_flow_info *flowInfo)
{
	flowID->first_IP = pkt->src_addr.s_addr;
	flowID->second_IP = pkt->dst_addr.s_addr;
	flowID->first_port = pkt->src_port;
	flowID->second_port = pkt->dst_port;
	flowID->ip_protocol = pkt->ip_p;
	flowInfo->begin = pkt->capture_time;
	flowInfo->last = pkt->capture_time;
	flowInfo->fstTOsnd_bytes = pkt->len;
	flowInfo->sndTOfst_bytes = 0;
	flowInfo->fstTOsnd_pkts_NO = 1;
	flowInfo->sndTOfst_pkts_NO = 0;
}
