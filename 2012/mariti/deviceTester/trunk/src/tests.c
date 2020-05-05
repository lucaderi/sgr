/**
 * gcc -c deviceTester.c 
 * gcc -Wall -pedantic tests.c -o tests deviceTester.o
 */
#define __USE_BSD
#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#include "utils.h"
#include "deviceTester.h"

int packetData_cmp__test0(void) {
  pcap_t *file;
  char errbuf[PCAP_ERRBUF_SIZE];
  int datalink, i=0;
  char *names[] = {
    "../captures/ping.pcap",
    "../captures/SkypeIRC.cap",
    NULL
  };
  while (names[i]) {
    const u_char *bytes;
    struct pcap_pkthdr h;
    ERRHAND_PC_EB(NULL, file = pcap_open_offline(names[i], errbuf));
    datalink = pcap_datalink(file);
    while (NULL != (bytes = pcap_next(file, &h))) {
      if (packetData_cmp(datalink, bytes, h.caplen, bytes, h.caplen))
	return 1;
    }
    i++;
  }
  return 0;
}

int main() {
  int result = 0;
  result = packetData_cmp__test0();
  return result;
}
