#ifndef PKT_INFO_H_
#define PKT_INFO_H_

#include <netinet/ip.h>
#include <arpa/inet.h>

typedef struct pkt_info
{
	time_t capture_time;
	u_char ip_p; /* ip protocol */
/**********************************************************
 * these fields are relevant only if ip_p == 6 (TCP)  	  *
 *														  */
# ifdef __FAVOR_BSD										/**/
	u_int8_t TCPflags;									/**/
# else /* !__FAVOR_BSD */								/**/
#  if __BYTE_ORDER == __LITTLE_ENDIAN					/**/
    u_int16_t res1:4;									/**/
    u_int16_t doff:4;									/**/
    u_int16_t fin:1;									/**/
    u_int16_t syn:1;									/**/
    u_int16_t rst:1;									/**/
    u_int16_t psh:1;									/**/
    u_int16_t ack:1;									/**/
    u_int16_t urg:1;									/**/
    u_int16_t res2:2;									/**/
#  elif __BYTE_ORDER == __BIG_ENDIAN					/**/
    u_int16_t doff:4;									/**/
    u_int16_t res1:4;									/**/
    u_int16_t res2:2;									/**/
    u_int16_t urg:1;									/**/
    u_int16_t ack:1;									/**/
    u_int16_t psh:1;									/**/
    u_int16_t rst:1;									/**/
    u_int16_t syn:1;									/**/
    u_int16_t fin:1;									/**/
#  else													/**/
#   error "Adjust your <bits/endian.h> defines"			/**/
#  endif												/**/
# endif /* __FAVOR_BSD */								/**/
/**********************************************************/
	struct in_addr src_addr;
	struct in_addr dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	u_int len;
} t_pkt_info;

void getCaptureTime(t_pkt_info *info, char *time_buf, int buf_size);
u_char getPktProtocol(t_pkt_info *info, char *protocol);
char * getSrcAddr(t_pkt_info *info);
uint16_t getSrcPort(t_pkt_info *info);
char * getDstAddr(t_pkt_info *info);
uint16_t getDstPort(t_pkt_info *info);
unsigned int toHash(t_pkt_info *info);

#endif /*PKT_INFO_H_*/
