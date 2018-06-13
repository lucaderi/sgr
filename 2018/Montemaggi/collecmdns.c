
#ifndef NDPI_UTIL_H
#define NDPI_UTIL_H

#include "ndpi_util.h"
#endif
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <libndpi/ndpi_main.h>
#define PCAP_SNAPLEN 65535
#define PCAP_PROMISC 1 
#define PCAP_TIMEOUT 300
#define true  1 
#define false 0

/*show help */
void printhelp()
{
	fprintf(stderr,"Usage [options] \n"
		       "Options:\n"
		       "-i device  your avalable device \n"
		       "-h show this help \n"
			);

}

/*set up option */
char * setupopt(int argc,char **argv)
{
	int c;char *device=NULL;
	while((c = getopt(argc,argv,"i:h")) !=-1)
	{
		switch(c)
		{
		case 'i':
		  device = optarg;
		  break;
		case 'h':
		  printhelp();
		  break;
		default:
		  printhelp();
		  break;
		}
	}

return device;	
}

/*function execute when mdns packet found*/
static void onfindmdns(struct ndpi_workflow *workflow,struct ndpi_flow_info *flow,void *data)
{
	struct ndpi_packet_struct *packet = &flow->ndpi_flow->packet;
	/*check payload and if there is a answer in packet copy in a ndpi struct*/
	
	ndpi_int_check_mdns_payload(workflow->ndpi_struct,flow->ndpi_flow);	
	
}

/*register a callback*/
void callback_pcap(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{

	ndpi_workflow_process_packet((struct ndpi_workflow*)args,header,packet);
}


int main(int argc,char **argv)
{
	char pcap_error_buf[PCAP_ERRBUF_SIZE];
	pcap_t *device=NULL;
	char *dev=NULL;
	struct ndpi_workflow_prefs prefs;
	struct ndpi_workflow *workflow;

	dev = setupopt(argc,argv);
	if(dev==NULL)return EXIT_FAILURE;	
	/*open a device for scanning */
	device = pcap_open_live(dev,PCAP_SNAPLEN,PCAP_PROMISC,PCAP_TIMEOUT,pcap_error_buf);	
	if(device==NULL)
	{
		perror("device");
		return EXIT_FAILURE;
	}

	
	memset(&prefs,0,sizeof(prefs));
	prefs.decode_tunnels=false;
	prefs.num_roots = 10;
	prefs.max_ndpi_flows = 100;
	prefs.quiet_mode = true;
	workflow= ndpi_workflow_init(&prefs,device);
	//function to call for packet mdns
	ndpi_workflow_set_flow_detected_callback(workflow,onfindmdns,NULL);
	if(workflow ==NULL )return EXIT_FAILURE;	
	
	//set bitmask for search mdns protocol	
	NDPI_PROTOCOL_BITMASK mdns;
	NDPI_BITMASK_RESET(mdns);
	NDPI_BITMASK_ADD(mdns,NDPI_PROTOCOL_MDNS);
	ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct,&mdns);
	
	if(workflow->pcap_handle !=NULL){
		pcap_loop(workflow->pcap_handle,-1,&callback_pcap,(u_char*)workflow);
	}
	else
	{
		fprintf(stderr,"pcap_handle is NULL");
		return EXIT_FAILURE;
	}

	
	return 0;
}
