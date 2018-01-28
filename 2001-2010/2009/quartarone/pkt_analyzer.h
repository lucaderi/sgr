#include <time.h>
#include <sys/time.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void loopPacket(u_char *file,const struct pcap_pkthdr *pkt,const u_char *p);

void process_ip(struct ip *ip);

void process_tcp(struct tcphdr *tcp);

void process_udp(struct udphdr *udp);

