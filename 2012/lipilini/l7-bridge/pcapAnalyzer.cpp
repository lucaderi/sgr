#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include <pcap.h>

#include "globals.h"

using namespace std;

flowHashTable * pcap_fHT = NULL;
flowKey_t pcap_flow_key;
bool pcap_upper_is_src;
struct ipoque_detection_module_struct * pcap_ipoque_struct = NULL;
IPOQUE_PROTOCOL_BITMASK pcap_ipq_proto_bitmask;

IPOQUE_PROTOCOL_BITMASK proto_found;

static unsigned int pcap_process_packet(const u_int64_t time, timeval ts, const struct iphdr *iph, void * th, u_int16_t ipsize){
  struct tcphdr * tcph = (struct tcphdr *)th;
  struct udphdr * udph = (struct udphdr *)th;

  u_int16_t src_port = 0;
  u_int16_t dst_port = 0;
  unsigned long n_bytes = 0;

  unsigned int detected_proto = 0;

  ip_addr src_ip;
  ip_addr dst_ip;

  memset(&src_ip, 0, sizeof(ip_addr));
  memset(&dst_ip, 0, sizeof(ip_addr));

  flowStruct * pFS = NULL;

  // build param for add_new_capt_pkt(...) in pcap hash table
  if (ipsize >= sizeof(struct iphdr)) {
    src_ip.v4 = iph->saddr;
    dst_ip.v4 = iph->daddr;
    if(iph->protocol == IPPROTO_TCP){
      src_port = tcph->source;
      dst_port = tcph->dest;
      n_bytes = ipsize - sizeof(struct tcphdr);
    }
    else if(iph->protocol == IPPROTO_UDP){
				src_port = udph->source;
				dst_port = udph->dest;
				n_bytes = udph->len;
    }
    else{
				return 1;
    }
  }else{
    return 1;
  }
  
  // build flow key
  build_flow_key(4, iph->protocol, &src_ip, src_port, &dst_ip, dst_port, &(pcap_flow_key), &(pcap_upper_is_src));

  // add pkt info to pcap hash table
  pFS = pcap_fHT->add_new_capt_pkt(&(pcap_flow_key), pcap_upper_is_src, n_bytes, &ts, &ts);

  // here the actual detection is performed
  if(pFS->get_src_ip()->v4 == src_ip.v4){
    detected_proto = ipoque_detection_process_packet(pcap_ipoque_struct, pFS->get_addr_of_nDPI_flow(),
											(u_char *) iph, ipsize, time, pFS->get_addr_of_nDPI_src() , pFS->get_addr_of_nDPI_dst());
  }else{
    detected_proto = ipoque_detection_process_packet(pcap_ipoque_struct, pFS->get_addr_of_nDPI_flow(),
											(u_char *) iph, ipsize, time, pFS->get_addr_of_nDPI_dst() , pFS->get_addr_of_nDPI_src());
  }

  if(detected_proto != IPOQUE_PROTOCOL_UNKNOWN){
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(proto_found, detected_proto);
  }

  return 0;
}

static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet){
  struct iphdr *iph = (struct iphdr *) &packet[sizeof(struct ethhdr)];
  void * th = (void *) &packet[sizeof(struct ethhdr)+sizeof(struct iphdr)];
  u_int64_t when = ((u_int64_t) header->ts.tv_sec) * DEFAULT_TICK_RESOLUTION /* detection_tick_resolution */
										+ header->ts.tv_usec / (1000000 / DEFAULT_TICK_RESOLUTION) /* (1000000 / detection_tick_resolution) */;

  if(iph->version == 4){
    pcap_process_packet(when, header->ts, iph, th, header->caplen - sizeof(struct ethhdr));
  }
}

void analyzePcapFile(char * _pcap_file){
	int i;
	pcap_t * pcap_descr = NULL;
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  
  printf("\nPcap Mode ON ! Initializing ...\n\n");

	printf("Creating flow hash table ... ");
  pcap_fHT = new (nothrow) flowHashTable(hash_table_size);
  if(pcap_fHT == NULL){
		printf("Can't create flow hash table for pcap analyze !\n");
		exit(EXIT_FAILURE);
	}
	printf("DONE !\n");
  
  printf("Creating ipq detection module ... ");
  pcap_ipoque_struct = ipoque_init_detection_module(DEFAULT_TICK_RESOLUTION, calloc_wrapper, NULL);
  if(pcap_ipoque_struct == NULL){
		printf("Can't create ipq detection module for pcap analyze !\n");
		exit(EXIT_FAILURE);
	}
	printf("DONE !\n");
  
  IPOQUE_BITMASK_SET_ALL(pcap_ipq_proto_bitmask);
  ipoque_set_protocol_detection_bitmask2(pcap_ipoque_struct, &pcap_ipq_proto_bitmask);
  
  IPOQUE_BITMASK_RESET(proto_found);

	printf("Opening file ... ");
  pcap_descr = pcap_open_offline(_pcap_file, pcap_errbuf);
  if(pcap_descr == NULL){
    perror("Can't open pcap file! Quitting...");
    exit(EXIT_FAILURE);
  }
  printf("DONE !\n");
  
  printf("\n\tNote : IPv6 packet are skipped !\n");
  printf("\tNote : Only TCP or UDP packet are considered !\n");

  printf("\nStarting file analysis ...\n\n");
  
  pcap_loop(pcap_descr, -1, &pcap_packet_callback, NULL);
  
  printf("Protocol found :\n");
	for(i=0; i<IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++){
		if(IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(proto_found, i) != 0){
			printf("\t%s \n", protocol_long_str[i]);
		}	
	}
  
  printf("\nExiting ... ");
  
  pcap_close(pcap_descr);
  delete pcap_fHT;
  ipoque_exit_detection_module(pcap_ipoque_struct, free_wrapper);
  
  printf("BYE !\n\n");
  
  return;
}
