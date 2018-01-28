#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include <pcap.h>
#include "flowHashTable.h"

#include "flowUtil.h"
#include "ipUtil.h"
#include "timeUtil.h"

#include "ipq_api.h"

#define DEFAULT_TICK_RESOLUTION 1000

flowHashTable * pcap_fHT = NULL;
flowKey_t pcap_flow_key;
bool pcap_upper_is_src;
struct ipoque_detection_module_struct * pcap_ipoque_struct = NULL;
IPOQUE_PROTOCOL_BITMASK pcap_ipq_proto_bitmask;

unsigned long long tot_pkt = 0;

bool ht_full = false;

unsigned long long pkt_processed = 0;
unsigned long long before_cpucycle, after_cpucycle, diff_cpucycle;

unsigned long long add_sum_cpucycle = 0;
unsigned long long add_qsum_cpucycle = 0;
unsigned long long add_n_under_cpucycle = 0;
unsigned long long add_n_in_cpucycle = 0;
unsigned long long add_n_over_cpucycle = 0;
unsigned long long add_max_cpucycle = 0;
unsigned long long add_min_cpucycle = ULONG_MAX;
unsigned long long add_max_packet, add_min_packet;
long double add_dev_cpucycle;

unsigned long long det_sum_cpucycle = 0;
unsigned long long det_qsum_cpucycle = 0;
unsigned long long det_n_under_cpucycle = 0;
unsigned long long det_n_in_cpucycle = 0;
unsigned long long det_n_over_cpucycle = 0;
unsigned long long det_max_cpucycle = 0;
unsigned long long det_min_cpucycle = ULONG_MAX;
unsigned long long det_max_packet, det_min_packet;
long double det_dev_cpucycle;

static unsigned int pcap_process_packet(const u_int64_t time, timeval ts, const struct iphdr * iph, void * th, u_int16_t ipsize);
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);

static void * calloc_wrapper(unsigned long size){
  return calloc(1, size);
}

static void free_wrapper(void * freeable){
  free(freeable);
}

using namespace std;

int main(int argc, char *argv[]){
	char c;
	
	char * pcap_file = NULL;
	pcap_t * pcap_descr = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	
	int hash_table_size = 10000;
	
	while((c = getopt(argc,argv,"p:s:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
			case 'p':
				pcap_file = strdup(optarg);
				break;
			case 's':
				hash_table_size = atoi(optarg);
				break;
    }
  }
  
  setbuf(stdout, NULL);
  
  pcap_fHT = new flowHashTable(hash_table_size);
  pcap_ipoque_struct = ipoque_init_detection_module(DEFAULT_TICK_RESOLUTION, calloc_wrapper, NULL);
  IPOQUE_BITMASK_SET_ALL(pcap_ipq_proto_bitmask);
  ipoque_set_protocol_detection_bitmask2(pcap_ipoque_struct, &pcap_ipq_proto_bitmask);

  if(pcap_file == NULL){
		printf("Select a pcap file !\n");
		return -1;
	}

  pcap_descr = pcap_open_offline(pcap_file, pcap_errbuf);

  pcap_loop(pcap_descr, -1, &pcap_packet_callback, NULL);
  
  pcap_close(pcap_descr);
  
  // calc deviation
  add_dev_cpucycle = (sqrt(((pkt_processed * add_qsum_cpucycle) - pow(add_sum_cpucycle, 2)))) / pkt_processed;
  det_dev_cpucycle = (sqrt(((pkt_processed * det_qsum_cpucycle) - pow(det_sum_cpucycle, 2)))) / pkt_processed;
  
  printf("\n--- STATISTIC ---\n\n");
  
  printf("Total pkt : %llu\n", tot_pkt);
  printf("Pkt processed : %llu\n\n", pkt_processed);
  
  printf("flowNum : %u\n\n", pcap_fHT->get_flowNum());
  
  printf("HT full : %s\n", (ht_full) ? "true" : "false" );
  printf("Add MAX cycle : %llu @ %llu\n", add_max_cpucycle, add_max_packet);
  printf("Add MIN cycle : %llu @ %llu\n", add_min_cpucycle, add_min_packet);
  printf("Add AVG cycle : %llu\n", add_sum_cpucycle / pkt_processed);
  printf("Add UNDER 400 cycle : %llu (%.2f%%)\n", add_n_under_cpucycle, (double) add_n_under_cpucycle / pkt_processed * 100);
  printf("Add [400 , 1300) cycle : %llu (%.2f%%)\n", add_n_in_cpucycle, (double) add_n_in_cpucycle / pkt_processed * 100);
  printf("Add OVER 1300 cycle : %llu (%.2f%%)\n", add_n_over_cpucycle, (double) add_n_over_cpucycle / pkt_processed * 100);
  printf("Add DEV cycle : %.2Lf\n\n", add_dev_cpucycle);
  
  printf("Det MAX cycle : %llu @ %llu\n", det_max_cpucycle, det_max_packet);
  printf("Det MIN cycle : %llu @ %llu\n", det_min_cpucycle, det_min_packet);
  printf("Det AVG cycle : %llu\n", det_sum_cpucycle / pkt_processed);
  printf("Det UNDER 1000 cycle : %llu (%.2f%%)\n", det_n_under_cpucycle, (double) det_n_under_cpucycle / pkt_processed * 100);
  printf("Det [1000 , 1500) cycle : %llu (%.2f%%)\n", det_n_in_cpucycle, (double) det_n_in_cpucycle / pkt_processed * 100);
  printf("Det OVER 1500 cycle : %llu (%.2f%%)\n", det_n_over_cpucycle, (double) det_n_over_cpucycle / pkt_processed * 100);
  printf("Det DEV cycle : %.2Lf\n\n", det_dev_cpucycle);
  
  //pcap_fHT->print_flow_hash_table();
  delete pcap_fHT;
  ipoque_exit_detection_module(pcap_ipoque_struct, free_wrapper);
  free(pcap_file);
  
  return 0;
	
}

static unsigned int pcap_process_packet(const u_int64_t time, timeval ts, const struct iphdr *iph, void * th, u_int16_t ipsize){
  struct tcphdr * tcph = (struct tcphdr *)th;
  struct udphdr * udph = (struct udphdr *)th;

  u_int16_t src_port = 0;
  u_int16_t dst_port = 0;
  unsigned long n_bytes = 0;

  ip_addr src_ip;
  ip_addr dst_ip;

  memset(&src_ip, 0, sizeof(ip_addr));
  memset(&dst_ip, 0, sizeof(ip_addr));

  flowStruct * pFS = NULL;

  // build parameters for add_new_capt_pkt(...) in pcap hash table
  src_ip.v4 = ntohl(iph->saddr);
  dst_ip.v4 = ntohl(iph->daddr);
    
  if(iph->protocol == IPPROTO_TCP){
    src_port = ntohs(tcph->source);
    dst_port = ntohs(tcph->dest);
    n_bytes = ipsize - sizeof(struct tcphdr);
  }
  else if(iph->protocol == IPPROTO_UDP){
      src_port = ntohs(udph->source);
      dst_port = ntohs(udph->dest);
      n_bytes = ntohs(udph->len);
  }
  else{
    return 1;
  }
  
  // build flow key
  build_flow_key(4, iph->protocol, &src_ip, src_port, &dst_ip, dst_port, &(pcap_flow_key), &(pcap_upper_is_src));
  
  // add pkt info to pcap hash table
  before_cpucycle = rdtsc();

  // add pkt info to pcap hash table
  pFS = pcap_fHT->add_new_capt_pkt(&(pcap_flow_key), pcap_upper_is_src, n_bytes, &ts, &ts);
  
  after_cpucycle = rdtsc();
  
	diff_cpucycle = after_cpucycle - before_cpucycle;
  
  // threshold stats 
  if(diff_cpucycle < 400){
    add_n_under_cpucycle++;
  }
  else if(400 <= diff_cpucycle && diff_cpucycle <= 1300){
    add_n_in_cpucycle++;
  }
  else if(1300 < diff_cpucycle){
    add_n_over_cpucycle++;
  }

	add_sum_cpucycle += diff_cpucycle;
  add_qsum_cpucycle += pow(diff_cpucycle, 2);
  
  if(diff_cpucycle > add_max_cpucycle){
    add_max_cpucycle = diff_cpucycle;
    add_max_packet = tot_pkt;
  }
  
  if(diff_cpucycle < add_min_cpucycle){
    add_min_cpucycle = diff_cpucycle;
    add_min_packet = tot_pkt;
  }
  
  pkt_processed++;

  if(pFS == NULL){
		ht_full = true;
		return 1;
	}


  // here the actual detection is performed
  if(equal_ipv4(pFS->get_src_ip()->v4, src_ip.v4)){
    before_cpucycle = rdtsc();
    
    ipoque_detection_process_packet(pcap_ipoque_struct, pFS->get_addr_of_nDPI_flow(),
											(u_char *) iph, ipsize, time, pFS->get_addr_of_nDPI_src() , pFS->get_addr_of_nDPI_dst());
    
    after_cpucycle = rdtsc();
  }else{
    before_cpucycle = rdtsc();
    
    ipoque_detection_process_packet(pcap_ipoque_struct, pFS->get_addr_of_nDPI_flow(),
											(u_char *) iph, ipsize, time, pFS->get_addr_of_nDPI_dst() , pFS->get_addr_of_nDPI_src());
    
    after_cpucycle = rdtsc();
  }
  
  diff_cpucycle = after_cpucycle - before_cpucycle;
    
  // threshold stats 
  if(diff_cpucycle < 1000){
    det_n_under_cpucycle++;
  }
  else if(1000 <= diff_cpucycle && diff_cpucycle <= 1500){
    det_n_in_cpucycle++;
  }
  else if(1500 < diff_cpucycle){
    det_n_over_cpucycle++;
  }

  det_sum_cpucycle += diff_cpucycle;
  det_qsum_cpucycle += pow(diff_cpucycle, 2);

  if(diff_cpucycle > det_max_cpucycle){
    det_max_cpucycle = diff_cpucycle;
    det_max_packet = tot_pkt;
  }

  if(diff_cpucycle < det_min_cpucycle){
    det_min_cpucycle = diff_cpucycle;
    det_min_packet = tot_pkt;
  }
  
  return 0;
}

static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet){
  struct ethhdr * ethernet_header = (struct ethhdr *) packet;
  struct iphdr * iph = (struct iphdr *) &packet[sizeof(struct ethhdr)];
  void * th = (void *) &packet[sizeof(struct ethhdr)+sizeof(struct iphdr)];
  u_int64_t when = ((u_int64_t) header->ts.tv_sec) * DEFAULT_TICK_RESOLUTION /* detection_tick_resolution */
										+ header->ts.tv_usec / (1000000 / DEFAULT_TICK_RESOLUTION) /* (1000000 / detection_tick_resolution) */;
  u_int16_t size = header->caplen - sizeof(struct ethhdr);
  
  tot_pkt++;
  
  if(iph->version == 4 && ethernet_header->h_proto != 0x0806 && size >= sizeof(struct iphdr)){
    pcap_process_packet(when, header->ts, iph, th, size);
  }
  
  return;
}

