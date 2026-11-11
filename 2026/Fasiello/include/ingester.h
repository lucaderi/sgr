#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

void offline_packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void ingest_packets_file(const char *filename);
