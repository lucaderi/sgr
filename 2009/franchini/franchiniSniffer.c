#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>

#include "hash.h"

pcap_t *in_pcap;
int datalink;
/**contatori**/
int tcp_count, udp_count, ip4_count, ip6_count, arp_count, icmp_count;
char *file_rrd = NULL, *file_png = NULL;
int step;
hashTable_t *hTable;

static void help() {
  printf("franchiniSniffer -s Step [-p File.png -r File.rrd] [-i Infile.pcap]\n\n");
  printf("Con la solo opzione -s viene sniffato il traffico direttamente dall'interfaccia di rete.\n");
  exit(0);
}

void changeUser() {
   struct passwd *pw = NULL;

   if(getuid() == 0) {
     /* We're root */
     char *user;
     
     pw = getpwnam(user = "alessandro");
     
     if(pw != NULL) {
       if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
         printf("Unable to change user to %s [%d: %d]: sticking with root\n", user, pw->pw_uid, pw->pw_gid);
       else
         printf("n2disk changed user to %s\n", user);
     }
   }
}

void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p) {
  int hlen = 0;
  struct ether_header ehdr;
  struct ip ip;
  struct ip6_hdr ip6;
  u_short eth_type;
  char *protocol; /***ipSrc, *ipDest, *bpf_filter = "udp and tcp";**/
  char *timestamp1 = (char *) ctime(&h->ts.tv_sec);
  time_t timestamp = h->ts.tv_sec;
  /**livello datalink**/
  if(datalink == DLT_EN10MB){
    memcpy(&ehdr, p + hlen, sizeof(struct ether_header));
    hlen += sizeof(struct ether_header);
    eth_type = ntohs(ehdr.ether_type);
    if(hlen >= h->caplen) return;
  }else if(datalink == DLT_PPP){
    hlen += 4;
    eth_type = ETHERTYPE_IP;
  }

  /**livello di rete **/
  if(eth_type == ETHERTYPE_IP){
    memcpy(&ip, p+hlen, sizeof(struct ip));
    if(ip.ip_v != 4) return;
    hlen += ((u_int)ip.ip_hl * 4);
    char * ipSrc, * ipDst;
    ip4_count += 1;
    if(hlen >= h->caplen) return;
    protocol = (getprotobynumber(ip.ip_p))->p_name;
    uint32_t ipSrcK = ip.ip_src.s_addr;
    uint32_t ipDstK = ip.ip_dst.s_addr;
    uint32_t key = ipSrcK + ipDstK;
    char * temp = inet_ntoa(ip.ip_src);
    int lung = strlen(temp) + 1;
    ipSrc = malloc(lung*sizeof(char));
    strncpy(ipSrc, temp, lung);
    temp = inet_ntoa(ip.ip_dst);
    lung = strlen(temp) + 1;
    ipDst = malloc(lung*sizeof(char));
    strncpy(ipDst, temp, lung);
    
    /**livello trasporto **/
    if(ip.ip_p == IPPROTO_TCP) {
      int plen;
      struct tcphdr tcp;
      memcpy(&tcp, p+hlen, sizeof(struct tcphdr));
      hlen += sizeof(struct tcphdr);
      plen = h->caplen - hlen;
      if(plen <= 0) return;
      tcp_count += 1;
      insertHash(hTable, protocol, key, ipSrc, ipDst, ntohs(tcp.source), ntohs(tcp.dest), h->len, timestamp);
      /**fprintf(stdout,"Timestamp: %s", timestamp);
      fprintf(stdout,"Protocol: %s\n",protocol);
      fprintf(stdout,"IpSrc:Port -> %s:%u\n", ipSrc, ntohs(tcp.source));
      fprintf(stdout,"IpDest:Port -> %s:%u\n\n", ipDst, ntohs(tcp.dest));
      fflush(stdout);**/
      
    }
    if(ip.ip_p == IPPROTO_UDP) {
      int plen;
      struct udphdr udp;
      memcpy(&udp, p+hlen, sizeof(struct udphdr));
      hlen += sizeof(struct udphdr);
      plen = h->caplen - hlen;
      if(plen <= 0) return;
      udp_count += 1;
      insertHash(hTable, protocol, key, ipSrc, ipDst, ntohs(udp.source), ntohs(udp.dest), h->len, timestamp);
      /**fprintf(stdout,"Timestamp: %s", timestamp);
      fprintf(stdout,"Protocol: %s\n",protocol);
      fprintf(stdout,"IpSrc:Port -> %s:%d\n", ipSrc, ntohs(udp.source));
      fprintf(stdout,"IpDest:Port -> %s:%d\n\n", ipDst, ntohs(udp.dest));
      fflush(stdout);**/
    }
    if(ip.ip_p == IPPROTO_ICMP) {
      icmp_count += 1;
      insertHash(hTable, protocol, key, ipSrc, ipDst, 0, 0, h->len, timestamp);
    }
  }
  if(eth_type == ETHERTYPE_IPV6){
    memcpy(&ip6, p+hlen, sizeof(struct ip6_hdr));
      
  }
  if(eth_type == ETHERTYPE_ARP){
    
  }
}

int createRrd(){
  char create[500]= "";
  sprintf(create, "rrdtool create %s --step=%d DS:tcp:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:2:1200 DS:udp:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:2:1200 DS:ip4:COUNTER:%d:0:10000 RRA:AVERAGE:0.5:2:1200", file_rrd, step, step*2, step*2, step*2);
  if(system(create) == -1){
    printf("Errore nella creazione del file.\n");
    return -1;
  }
  printf("%s\n",create);
  return 0;
}

int updateRrd(){
  char update[500] = "";
  sprintf(update, "rrdtool update %s --template=tcp:udp:ip4 N:%d:%d:%d", file_rrd, tcp_count, udp_count, ip4_count);
  if(system(update) == -1){
    printf("Errore nell'esecuzione di rrdtool update.\n");
    return -1;
  }
  printf("%s\n",update);
  return 0;
  
}

int printGraph(){
  char graph[500] = "";
  sprintf(graph, "rrdtool graph --start end-10m --width 800 --height 400 %s DEF:in1=%s:tcp:AVERAGE LINE:in1#0000ff:'Pacchetti Tcp' DEF:in2=%s:udp:AVERAGE LINE:in2#00ff00:'Pacchetti Udp' DEF:in3=%s:ip4:AVERAGE LINE:in3#ff0000:'Pacchetti Ip v4'", file_png, file_rrd, file_rrd, file_rrd);
  if(system(graph) == -1){
    printf("Errore nell'esecuzione di rrdtool graph.\n");
    return -1;
  }
}

void eventAlarm(){
  if(file_rrd != NULL && updateRrd()==-1)
    exit(errno);
  removeFromHash(hTable, step*4, time(NULL)); 
  alarm(step);
}

void eventStop(){
  if(file_png != NULL && printGraph()==-1)
    exit(errno);
  pcap_close(in_pcap);
  deleteHash(hTable);
  printf("Done\n");
  exit(0);
}

int main(int argc, char* argv[]) {
  char errbuf[256];
  struct pcap_pkthdr hdr;
  const u_char * pkt;
  char *dev;
  char arg;
  char *in_file = NULL;
  if(argc < 2)
    help();
  while((arg = getopt(argc, argv, "hr:p:s:i:"))!=-1){
    switch(arg){
    case 'r':
      file_rrd = strdup(optarg);
      break;
    case 'p':
      file_png = strdup(optarg);
      break;
    case 's':
      step = atoi(optarg);
      break;
    case 'i':
      in_file = strdup(optarg);
      break;
    }
  }  
  if((file_rrd != NULL && file_png == NULL) || (file_rrd == NULL && file_png != NULL))
	help();
  dev = pcap_lookupdev(errbuf);
  if(in_file == NULL){
    in_pcap = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	if(in_pcap == NULL) {
		printf("pcap_open: %s\n", errbuf);
		return(-1);
	}
  }
  else
    in_pcap = pcap_open_offline(in_file, errbuf);
  
  changeUser();
  datalink = pcap_datalink(in_pcap);
  if(file_rrd == NULL || file_png == NULL){
	FILE *rrd = fopen(file_rrd, "r");
	if(rrd == NULL){
		printf("Creazione file...\n");
		if(createRrd() == -1)
			return -1;
		else
		printf("File creato.\n");
	}
	else{
		printf("File già esistente. I dati verranno aggiunti.\n");
		fclose(rrd);
	}
  }
  signal(SIGALRM, eventAlarm);
  signal(SIGINT, eventStop);
  alarm(step);
  hTable = createHash(10000);

  if(in_file == NULL)
    while(1){
      pkt = pcap_next(in_pcap, &hdr);
      processPacket(NULL, &hdr, pkt);
    }
  else
    pcap_loop(in_pcap, -1, processPacket, NULL);
  return(0);    
}
