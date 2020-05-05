#ifndef DEVICETESTER_TYPES_H
#define DEVICETESTER_TYPES_H

#ifndef usec_t_defined
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <sys/types.h>
#define usec_t_defined
/**
 * data type that rappresent microsecond time value
 */
typedef u_int64_t  usec_t;
/* ??? */
#define USEC_T_MAX ULONG_MAX
#define PRI_USEC "%llu"
#endif 

#define PRI_UI64 "%llu"


#define PACKET_INTERFACE_A	0
#define PACKET_INTERFACE_B	1

/**
 * data structure that represent a captured packet stored in pcap file
 */
struct packet {
  usec_t	delta;		/* elapsed time between reception of
				 * this and previous packet */
  u_int32_t	len;		/* packet length */
  unsigned char	*data;		/* packet bytes */
  unsigned char	interface;	/* network interface on wihch to send
				 * this packet */
#ifndef NOPACKETLOST
  struct timeval test_send_ts;	/* timestamp of test send */
#endif
  struct packet *next;
};

struct list {
  struct packet *head;
  struct packet *tail;
  unsigned int size;
};

#endif	/* DEVICETESTER_TYPES_H */
