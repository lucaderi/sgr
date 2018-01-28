#ifndef DEVICETESTER_UTILS_H
#  define DEVICETESTER_UTILS_H

#define ERRHAND(VAL, TODO)						\
     if ((VAL) == (TODO)) { perror(#TODO); exit(EXIT_FAILURE); }

#define ERRHAND_GEN(VAL, TODO, HAND)		\
  if ((VAL) == (TODO)) { perror(#TODO); HAND; }

#define ERRHAND_PC_EB(VAL, TODO)					\
  if ((VAL) == (TODO)) { fprintf(stderr, "%s\n", errbuf); exit(EXIT_FAILURE); }

#define ERRHAND_PC_PE(VAL, TODO, PCAP)					\
  if ((VAL) == (TODO)) { pcap_perror(PCAP, #TODO); pcap_close(PCAP);	\
    exit(EXIT_FAILURE); }

#define ERRHAND_PC_GETERR(PCAP, STRERR)				\
  if ('\0' != *pcap_geterr(PCAP)) { pcap_perror(PCAP, STRERR);	\
    exit(EXIT_FAILURE); }

#endif	/* DEVICETESTER_UTILS_H */
