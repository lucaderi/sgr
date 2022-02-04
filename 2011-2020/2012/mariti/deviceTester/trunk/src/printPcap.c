/**
 * gcc -Wall -pedantic printPcap.c -o printPcap timeUtils.o deviceTester_impl.o -lpcap
 */
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <limits.h>
#include <getopt.h>
#include <string.h>

#include "types.h"
#include "deviceTester.h"
#include "utils.h"
#include "timeUtils.h"

void myprint(unsigned long a, int fieldsize, int collength) {
  static int n;
  if (collength < (n += printf("%-*lu ", fieldsize, a))) {
    printf("\n"); n=0;
  }
}

#define P_DELTA		1
#define P_LENGTH	2
#define P_INTERF	4
#define P_DATA		8

void printHelp(void) {
  printf("Usage: printPcap file [options]\n"
	 "options: d\t\t""print packet delta \n"
	 "         l\t\t""print packet length \n"
	 "         i\t\t""print packet output-interface \n"
	 "         D\t\t""print packet data \n"
	 "         p string\t""partition rule string \n"	 
	 );
}

int main(int argc, char **argv) {
  char *filename, errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *offline;
  struct list l = { NULL, NULL, 0 };
  struct packet *p, *prev;
  /* 0max 1min 2sum 3ssum */
  usec_t delta[4] = { 0, USEC_T_MAX, 0, 0};
  u_int64_t len[4] = { 0, UINT_MAX, 0, 0 };
  unsigned int numInterfA = 0;
  unsigned int numContigInterf[4] = { 0 };

  unsigned char args = 0;
  char *partrule = "none";
  int nextopt;
  optind = 2;

  if (1 == argc || !strcmp("-h", argv[1])) { printHelp(); exit(0); }

  while (-1 != (nextopt = getopt(argc, argv, "dliDhp:"))) 
    switch (nextopt) {
    case 'd': args |= P_DELTA; break;
    case 'l': args |= P_LENGTH; break;
    case 'i': args |= P_INTERF; break;
    case 'D': args |= P_DATA; break;
    case 'p': partrule = optarg; break;
    case 'h':
      printHelp();
      exit(0);
    default:
      printHelp();
      exit(EXIT_FAILURE);
    }

  filename = argv[1];
  ERRHAND_PC_EB(NULL, offline = pcap_open_offline(filename, errbuf));
  
  parsePcapFile(&l, offline, parsePartRule(partrule), 0);
  p=l.head;

  while (p) {
#define N 140
    if (args & P_INTERF) myprint(p->interface, 1, N);
    if (args & P_DELTA) myprint(p->delta, 10, N);

    if (p->delta > delta[0]) delta[0] = p->delta;
    if (p->delta < delta[1]) delta[1] = p->delta;
    delta[2] += p->delta;

    if (p->len > len[0]) len[0]=p->len;
    if (p->len < len[1]) len[1]=p->len;
    len[2] += p->len;

    if (NULL != prev && p->interface == prev->interface) {
      numContigInterf[p->interface] ++;
      if (numContigInterf[p->interface] > numContigInterf[p->interface+2]) {
	numContigInterf[p->interface+2] = numContigInterf[p->interface];
      }
    } else {
      numContigInterf[p->interface] = 0;
    }
    numInterfA += p->interface == 0 ? 1 : 0;

    prev = p; p=p->next;
  }

  if (args) printf("\n---\n");
  
  printf("num packets: %u \n"
	 "num bytes: %lu \n"
	 "num packets with out interfaces A: %u \n"
	 "max num contiguous out interf: %u A %u B \n"
	 "delta(usec): %lu max %lu min %f avg \n"
	 "capture lengths(bytes): %lu max %lu min %f min \n",
	 l.size,
	 (unsigned long) len[2],
	 numInterfA,
	 numContigInterf[2], numContigInterf[3],
	 (unsigned long)delta[0], (unsigned long)delta[1], ((double)delta[2]/l.size),
	 (unsigned long)len[0], (unsigned long)len[1], ((double)len[2]/l.size));
  
  return 0;
}
