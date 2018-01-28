/*
 * collectd - src/utils_http.c
 * Copyright (C) 2010  Daniele Sirigu
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of The Measurement Factory nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 
 * Author:
 *   Daniele Sirigu  <serdank at gmail.org>
 *
 * 
 */

#define _BSD_SOURCE


#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include <stdio.h>

#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#if HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#if HAVE_ARPA_NAMESER_COMPAT_H
# include <arpa/nameser_compat.h>
#endif

#if HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif
#if HAVE_NET_IF_H
# include <net/if.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif
#if HAVE_NET_PPP_DEFS_H
# include <net/ppp_defs.h>
#endif
#if HAVE_NET_IF_PPP_H
# include <net/if_ppp.h>
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif

#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_IP_VAR_H
# include <netinet/ip_var.h>
#endif
#if HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif
#if HAVE_NETINET_UDP_H
# include <netinet/udp.h>
#endif

#if HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#if HAVE_PCAP_H
# include <pcap.h>
#endif

#define PCAP_SNAPLEN 1460
#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif
#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q 0x8100
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#ifndef PPP_ADDRESS_VAL
# define PPP_ADDRESS_VAL 0xff	/* The address byte value */
#endif
#ifndef PPP_CONTROL_VAL
# define PPP_CONTROL_VAL 0x03	/* The control byte value */
#endif

/* On linux is in the /usr/include/netinet*/
#if HAVE_STRUCT_UDPHDR_UH_DPORT && HAVE_STRUCT_UDPHDR_UH_SPORT
# define UDP_DEST uh_dport
# define UDP_SRC  uh_dport
#elif HAVE_STRUCT_UDPHDR_DEST && HAVE_STRUCT_UDPHDR_SOURCE
# define UDP_DEST dest
# define UDP_SRC  source
#else
# error "`struct udphdr' is unusable."
#endif

#if HAVE_STRUCT_TCPHDR_TH_DPORT && HAVE_STRUCT_TCPHDR_TH_SPORT
# define TCP_DEST th_sport
# define TCP_SRC  th_dport
#elif HAVE_STRUCT_TCPHDR_DEST && HAVE_STRUCT_TCPHDR_SOURCE
# define TCP_DEST dest
# define TCP_SRC  source
#else
# error "`struct tcphdr' is unusable."
#endif

#include "utils_http.h"

/* linked list of ip structure */
struct ip_list_s
{
    struct in6_addr addr;
    void *data;
    struct ip_list_s *next;
};
typedef struct ip_list_s ip_list_t;

typedef int (printer)(const char *, ...);

/*flags/features for non-interactive mode */
#ifndef T_A6
#define T_A6 38
#endif
#ifndef T_SRV
#define T_SRV 33
#endif

/* Global variables declared in utils_http.h*/
int rm_type_counts[RM_MAX];
int sc_type_counts[SC_MAX];
int mime_type_counts[MM_MAX];

/* Variables, callbacks initialization */
#if HAVE_PCAP_H
static pcap_t *pcap_obj = NULL;
#endif
static ip_list_t *IgnoreList = NULL;
#if HAVE_PCAP_H
static void (*Callback) (const http_header_t *) = NULL;

static int query_count_intvl = 0;
static int query_count_total = 0;

# ifdef __OpenBSD__
static struct bpf_timeval last_ts;
# else
static struct timeval last_ts;
# endif /* __OpenBSD__ */
#endif /* HAVE_PCAP_H */

/*
* Compare two IPv6 addresses 
* @Return 0 if equals,  1 otherwise 	  
*/
static int cmp_in6_addr (const struct in6_addr *a, const struct in6_addr *b)
{
  int i;
  assert (sizeof (struct in6_addr) == 16);
  
  for (i = 0; i < 16; i++)
      if (a->s6_addr[i] != b->s6_addr[i])
	  break;

  if (i >= 16)
      return (0);

  return (a->s6_addr[i] > b->s6_addr[i] ? 1 : -1);
} /* int cmp_addrinfo */

/*
* Check if the input address match an address of the IgnoreList. 
* @return 0, if no match is found, 1 otherwise.
*/
static inline int ignore_list_match (const struct in6_addr *addr)
{
  ip_list_t *ptr;

  for (ptr = IgnoreList; ptr != NULL; ptr = ptr->next)
      if (cmp_in6_addr (addr, &ptr->addr) == 0)
	  return (1);
  return (0);
} /* int ignore_list_match */

/*
* Add an address to the IgnoreList
*/
static void ignore_list_add (const struct in6_addr *addr)
{
  ip_list_t *new;

  if (ignore_list_match (addr) != 0)
      return;

  new = malloc (sizeof (ip_list_t));
  if (new == NULL)
  {
      perror ("malloc");
      return;
  }

  memcpy (&new->addr, addr, sizeof (struct in6_addr));
  new->next = IgnoreList;

  IgnoreList = new;
} /* void ignore_list_add */

/*
* Add an address to the IgnoreList (by a name)
*/
void ignore_list_add_name (const char *name)
{
  struct addrinfo *ai_list;
  struct addrinfo *ai_ptr;
  struct in6_addr  addr;
  int status;

  status = getaddrinfo (name, NULL, NULL, &ai_list);
  if (status != 0)
      return;

  for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next)
  {
    if (ai_ptr->ai_family == AF_INET)
    {
      memset (&addr, '\0', sizeof (addr));
      addr.s6_addr[10] = 0xFF;
      addr.s6_addr[11] = 0xFF;
      memcpy (addr.s6_addr + 12, &((struct sockaddr_in *) ai_ptr->ai_addr)->sin_addr, 4);

      ignore_list_add (&addr);
    }
    else
    {
      ignore_list_add (&((struct sockaddr_in6 *) ai_ptr->ai_addr)->sin6_addr);
    }
  } /* for */

  freeaddrinfo (ai_list);
}

#if HAVE_PCAP_H
/*
* Set the an ipV6 address using a buffer 
*/
static void in6_addr_from_buffer (struct in6_addr *ia,const void *buf, size_t buf_len, int family)
{
  memset (ia, 0, sizeof (struct in6_addr));
  if ((AF_INET == family) && (sizeof (uint32_t) == buf_len))
  {
    ia->s6_addr[10] = 0xFF;
    ia->s6_addr[11] = 0xFF;
    memcpy (ia->s6_addr + 12, buf, buf_len);
  }
  else if ((AF_INET6 == family) && (sizeof (struct in6_addr) == buf_len))
  {
    memcpy (ia, buf, buf_len);
  }
} /* void in6_addr_from_buffer */

/*
* Set the network device that will be sniffed
*/
void http_set_pcap_obj (pcap_t *po)
{
  pcap_obj = po;
} /* void http_set_pcap_obj */

/*
* Set the callback that sent the values to collectd
*/
void http_set_callback (void (*cb) (const http_header_t *))
{
  Callback = cb;
} /* void http_set_callback */

#define RFC1035_MAXLABELSZ 63

/*
* Check what type of mime corresponds to the input string
* @return: the corresponding mime type if a match has been found
* 	 -1 if no match has been found
*/
static int mime_check(const char *tocheck)
{
  DEBUG("DBGHTTP MIMECHECK=%s",tocheck);

  if (!strncmp(tocheck,"application",11))
      return MIME_APPLICATION;
  if (!strncmp(tocheck,"audio",5))
      return MIME_AUDIO;
  if (!strncmp(tocheck,"example",7))
      return MIME_EXAMPLE;
  if (!strncmp(tocheck,"image",5))
      return MIME_IMAGE;
  if (!strncmp(tocheck,"message",7))
      return MIME_MESSAGE;
  if (!strncmp(tocheck,"model",5))
      return MIME_MODEL;
  if (!strncmp(tocheck,"multipart",9))
      return MIME_MULTIPART;
  if (!strncmp(tocheck,"text",4))
      return MIME_TEXT;
  if (!strncmp(tocheck,"video",5))
      return MIME_VIDEO;

  DEBUG("DBGHTTP MIMEERROR: %s",tocheck);
  return -1;
}

/*
*Check what type of request method corresponds to the input string
*@return: the corresponding request method if there has been found a match
*	-1 if no match has been found
*/
static int request_method_check(const char *tocheck)
{

  if (!strncmp(tocheck,"OPTIONS",7))
      return RM_OPTIONS;
  if (!strncmp(tocheck,"GET",3))
      return RM_GET;
  if (!strncmp(tocheck,"HEAD",4))
      return RM_HEAD;
  if (!strncmp(tocheck,"POST",4))
      return RM_POST;
  if (!strncmp(tocheck,"PUT",3))
      return RM_PUT;
  if (!strncmp(tocheck,"DELETE",6))
      return RM_DELETE;
  if (!strncmp(tocheck,"TRACE",3))
      return RM_TRACE;
  if (!strncmp(tocheck,"CONNECT",6))
      return RM_CONNECT;

  return -1; //other data
}

/*
*Check what type of status code corresponds to the input string
*@return: the corresponding status code if there has been found a match
*	-1 if no match has been found
*/
static int status_code_check(const char *tocheck)
{
  if (!strcmp(tocheck,"100"))
      return SC_100;
  if (!strcmp(tocheck,"101"))
      return SC_101;
  if (!strcmp(tocheck,"200"))
      return SC_200;
  if (!strcmp(tocheck,"201"))
      return SC_201;
  if (!strcmp(tocheck,"202"))
      return SC_202;
  if (!strcmp(tocheck,"203"))
      return SC_203;
  if (!strcmp(tocheck,"204"))
      return SC_204;
  if (!strcmp(tocheck,"205"))
      return SC_205;
  if (!strcmp(tocheck,"206"))
      return SC_206;
  if (!strcmp(tocheck,"300"))
      return SC_300;
  if (!strcmp(tocheck,"301"))
      return SC_301;
  if (!strcmp(tocheck,"302"))
      return SC_302;
  if (!strcmp(tocheck,"303"))
      return SC_303;
  if (!strcmp(tocheck,"304"))
      return SC_304;
  if (!strcmp(tocheck,"305"))
      return SC_305;
  if (!strcmp(tocheck,"306"))
      return SC_306;
  if (!strcmp(tocheck,"307"))
      return SC_307;
  if (!strcmp(tocheck,"400"))
      return SC_400;
  if (!strcmp(tocheck,"401"))
      return SC_401;
  if (!strcmp(tocheck,"402"))
      return SC_402;
  if (!strcmp(tocheck,"403"))
      return SC_403;
  if (!strcmp(tocheck,"404"))
      return SC_404;
  if (!strcmp(tocheck,"405"))
      return SC_405;
  if (!strcmp(tocheck,"406"))
      return SC_406;
  if (!strcmp(tocheck,"407"))
      return SC_407;
  if (!strcmp(tocheck,"408"))
      return SC_408;
  if (!strcmp(tocheck,"409"))
      return SC_409;
  if (!strcmp(tocheck,"410"))
      return SC_410;
  if (!strcmp(tocheck,"411"))
      return SC_411;
  if (!strcmp(tocheck,"412"))
      return SC_412;
  if (!strcmp(tocheck,"413"))
      return SC_413;
  if (!strcmp(tocheck,"414"))
      return SC_414;
  if (!strcmp(tocheck,"415"))
      return SC_415;
  if (!strcmp(tocheck,"416"))
      return SC_416;
  if (!strcmp(tocheck,"417"))
      return SC_417;
  if (!strcmp(tocheck,"500"))
      return SC_500;
  if (!strcmp(tocheck,"501"))
      return SC_501;
  if (!strcmp(tocheck,"502"))
      return SC_502;
  if (!strcmp(tocheck,"503"))
      return SC_503;
  if (!strcmp(tocheck,"504"))
      return SC_504;
  if (!strcmp(tocheck,"505"))
      return SC_505;
  
  return -1; /*other status code*/
}

/*
* Handle the HTTP part of the packet. Set the http_header_t structure depending on the packet data.
*/
static int handle_http(const char *buf, int len)
{

  char httpbuf[PCAP_SNAPLEN];
  memcpy(httpbuf, buf, len);

  /*
  printf("DBGHTTP\n\n\n\n");
  printf("DBGHTTP TEST c="); 
  int zz=0;
  unsigned char nen;
  for(zz=0;zz<len;zz++)
  {
    nen = httpbuf[zz];
    printf("%c ",&nen);
  }
  */
  
  http_header_t hh;

  /*Default type of the packet*/
  hh.packet_type = PT_OTHER;
  hh.length=(uint16_t) len;
  hh.has_mime_type=0;

  char aux_typackt[10];
  char stat_code[4];

  strncpy(aux_typackt, httpbuf, 9);
  aux_typackt[10] = '\0';

  char aux_contentpacket[30];
  strncpy(aux_contentpacket, httpbuf, 29);
  aux_contentpacket[30] = '\0';
   
  DEBUG("DBGHTTP CONTENTPACKET %s",aux_contentpacket);
  
  
    
  /*Check if the packet contains an HTTP Response header */ 
  if(aux_typackt[0] == 'H' && aux_typackt[1] == 'T' && aux_typackt[2] == 'T' && aux_typackt[3] == 'P')
  {
    hh.packet_type=PT_HEADER_RESPONSE;

    DEBUG("DBGHTTP HTTPOK %s",aux_typackt);

    strncpy(stat_code,&httpbuf[9],3);
    stat_code[3]='\0';

    DEBUG("DBGHTTP HTTPCODE %s",stat_code);

    int scchk=status_code_check(stat_code);

    DEBUG("DBGHTTP scchk %d",scchk);

    if (scchk != -1)
	hh.status_code=scchk;

    char content_header[PCAP_SNAPLEN];
    strncpy(content_header, httpbuf, PCAP_SNAPLEN);
    content_header[PCAP_SNAPLEN]='\0';

    /* Check if there is an mime type in the packet and if present add it to the linked list of mime types  */
    char * pch;
    pch = strstr (content_header,"Content-Type: ");
    if (pch != NULL)
    {
      char aux_typmime[20];
      strncpy(aux_typmime, pch+14, 20);
      aux_typmime[20] = '\0';
      
      int mimchk=mime_check(aux_typmime);
      
      if (mimchk != -1)
      {
	hh.has_mime_type=1;
	hh.mime_type=mimchk;
	mime_type_counts[(int) hh.mime_type]++;
      }
	
    }
 
    /* Add the source code present in the packet to the linked list of source codes*/
    sc_type_counts[(int) hh.status_code]++;

  }
  else /* Request method */ 
  { 
    int req_met_chk=request_method_check(aux_typackt);
    DEBUG("DBGHTTP HTTPQ = %d",req_met_chk);

    /*If the packet contains an HTTP Request header*/
    if (req_met_chk != -1)
    {
      hh.packet_type=PT_HEADER_REQUEST;
      hh.request_method=req_met_chk;
      
      /* Add the request method present in the packet to the linked list of request methods*/
      rm_type_counts[(int) hh.request_method]++;
    }
    else /*Possible error or not http protocol or packet doesn't contain an http header */ 
    {
      DEBUG("DBGHTTP HTTP: packet doesn't contain an http header");
      hh.packet_type=PT_OTHER;
      
    }
  }

    if (Callback != NULL)
      Callback (&hh);
    else
      ERROR("DBGHTTP HTTP Error: Callback is null");

      return 1;
}

/*
* Handle the TCP part of the packet. 
*/
static int handle_tcp(const struct tcphdr *tcp, int len)
{
  char buf[PCAP_SNAPLEN];
  memcpy(buf, tcp + 1, len - sizeof(*tcp));
  DEBUG("DBGHTTP TCPDs tcp string: %s",buf);
   
  if (0 == handle_http(buf, len - sizeof(*tcp)))
    return 0;

return 1;
}

/*
* Handle the IPv6 part of the packet (if the packet has an IPv6 address). 
*/
static int handle_ipv6 (struct ip6_hdr *ipv6, int len)
{
  DEBUG("DBGHTTP IPV6");
  char buf[PCAP_SNAPLEN];
  unsigned int offset;
  int nexthdr;

  struct in6_addr s_addr;
  struct in6_addr d_addr;
  uint16_t payload_len;

  if (0 > len)
  return (0);

  offset = sizeof (struct ip6_hdr);
  nexthdr = ipv6->ip6_nxt;
  s_addr = ipv6->ip6_src;
  d_addr = ipv6->ip6_dst;
  payload_len = ntohs (ipv6->ip6_plen);

  if (ignore_list_match (&s_addr))
    return (0);

  /* Parse extension headers. This only handles the standard headers, as
  * defined in RFC 2460, correctly. Fragments are discarded. */
  while ((IPPROTO_ROUTING == nexthdr) /* routing header */
  || (IPPROTO_HOPOPTS == nexthdr) /* Hop-by-Hop options. */
  || (IPPROTO_FRAGMENT == nexthdr) /* fragmentation header. */
  || (IPPROTO_DSTOPTS == nexthdr) /* destination options. */
  || (IPPROTO_DSTOPTS == nexthdr) /* destination options. */
  || (IPPROTO_AH == nexthdr) /* destination options. */
  || (IPPROTO_ESP == nexthdr)) /* encapsulating security payload. */
  {
    struct ip6_ext ext_hdr;
    uint16_t ext_hdr_len;

    /* Catch broken packets */
    if ((offset + sizeof (struct ip6_ext)) > (unsigned int)len)
    return (0);

    /* Cannot handle fragments. */
    if (IPPROTO_FRAGMENT == nexthdr)
    return (0);

    memcpy (&ext_hdr, (char *) ipv6 + offset, sizeof (struct ip6_ext));
    nexthdr = ext_hdr.ip6e_nxt;
    ext_hdr_len = (8 * (ntohs (ext_hdr.ip6e_len) + 1));

    /* This header is longer than the packets payload.. WTF? */
    if (ext_hdr_len > payload_len)
    return (0);

    offset += ext_hdr_len;
    payload_len -= ext_hdr_len;
  } /* while */

  /* Catch broken and empty packets */
  if (((offset + payload_len) > (unsigned int)len) || (payload_len == 0) || (payload_len > PCAP_SNAPLEN))
    return (0);

  if(IPPROTO_TCP != nexthdr)
  {
    DEBUG("DBGHTTP TCPDip packet hasn't TCP header");
    return 0;
  }

  memcpy (buf, (char *) ipv6 + offset, payload_len);
  if (handle_tcp ((struct tcphdr *) buf, payload_len) == 0)
    return (0);

  return (1); /* Success */
} /* int handle_ipv6 */

/*
* Handle the IPv4 part of the packet (if the packet has an IPv4 packet).
*/
static int handle_ip(const struct ip *ip, int len)
{
  char buf[PCAP_SNAPLEN];
  int offset = ip->ip_hl << 2;
  struct in6_addr s_addr;
  struct in6_addr d_addr;

  if (ip->ip_v == 6)
    return (handle_ipv6 ((struct ip6_hdr *) ip, len));

  in6_addr_from_buffer (&s_addr, &ip->ip_src.s_addr, sizeof (ip->ip_src.s_addr), AF_INET);
  in6_addr_from_buffer (&d_addr, &ip->ip_dst.s_addr, sizeof (ip->ip_dst.s_addr), AF_INET);
  if (ignore_list_match (&s_addr))
    return (0);

  if (IPPROTO_TCP != ip->ip_p)
  {
    DEBUG("DBGHTTP TCPDip packet hasn't TCP header");
    return 0;
  }

  /*packet has a tcp header so handle the tcp header*/
  memcpy(buf, (void *) ip + offset, len - offset);

  if (0 == handle_tcp((struct tcphdr *) buf, len - offset))
    return 0;
  
  return 1;
}

/*
* Handle the PPP part of the packet
*/
#if HAVE_NET_IF_PPP_H
static int handle_ppp(const u_char * pkt, int len)
{
  char buf[PCAP_SNAPLEN];
  unsigned short us;
  unsigned short proto;
  if (len < 2)
    return 0;
  if (*pkt == PPP_ADDRESS_VAL && *(pkt + 1) == PPP_CONTROL_VAL)
    {
      pkt += 2;		/* ACFC not used */
      len -= 2;
    }
  if (len < 2)
    return 0;
  if (*pkt % 2)
    {
      proto = *pkt;		/* PFC is used */
      pkt++;
      len--;
    }
  else
    {
      memcpy(&us, pkt, sizeof(us));
      proto = ntohs(us);
      pkt += 2;
      len -= 2;
    }
  if (ETHERTYPE_IP != proto && PPP_IP != proto)
    return 0;
  memcpy(buf, pkt, len);
  return handle_ip((struct ip *) buf, len);
}
#endif /* HAVE_NET_IF_PPP_H */

/*
  Handle the "null" part of the packet
*/
static int handle_null(const u_char * pkt, int len)
{
  unsigned int family;
  memcpy(&family, pkt, sizeof(family));
  if (AF_INET != family)
  return 0;
  return handle_ip((struct ip *) (pkt + 4), len - 4);
} /* int handle_null */

/*
* Handle the OpenBSD DLT_LOOP part of the packet 
*/
#ifdef DLT_LOOP
static int handle_loop(const u_char * pkt, int len)
{
    unsigned int family;
    memcpy(&family, pkt, sizeof(family));
    if (AF_INET != ntohl(family))
    return 0;
    return handle_ip((struct ip *) (pkt + 4), len - 4);
}
#endif

/*
* Handle a row packet
*/
#ifdef DLT_RAW
static int handle_raw(const u_char * pkt, int len)
{
    return handle_ip((struct ip *) pkt, len);
}
#endif

/*
* Handle the ethernet part of the packet
*/
static int handle_ether(const u_char * pkt, int len)
{
  char buf[PCAP_SNAPLEN];
  struct ether_header *e = (void *) pkt;
  unsigned short etype = ntohs(e->ether_type);
  if (len < ETHER_HDR_LEN)
  return 0;
  pkt += ETHER_HDR_LEN;
  len -= ETHER_HDR_LEN;
  if (ETHERTYPE_8021Q == etype)
  {
    etype = ntohs(*(unsigned short *) (pkt + 2));
    pkt += 4;
    len -= 4;
  }
  if ((ETHERTYPE_IP != etype) && (ETHERTYPE_IPV6 != etype))
    return 0;
  memcpy(buf, pkt, len);
  if (ETHERTYPE_IPV6 == etype)
    return (handle_ipv6 ((struct ip6_hdr *) buf, len));
  else
    return handle_ip((struct ip *) buf, len);
}

/*
* Handle the Linux cooked sockets part of the packet
*/
#ifdef DLT_LINUX_SLL	
static int handle_linux_sll (const u_char *pkt, int len)
{
  struct sll_header
  {
    uint16_t pkt_type;
    uint16_t dev_type;
    uint16_t addr_len;
    uint8_t  addr[8];
    uint16_t proto_type;
  } *hdr;
  
  uint16_t etype;

  if ((0 > len) || ((unsigned int)len < sizeof (struct sll_header)))
    return (0);

  hdr  = (struct sll_header *) pkt;
  pkt  = (u_char *) (hdr + 1);
  len -= sizeof (struct sll_header);

  etype = ntohs (hdr->proto_type);

  if ((ETHERTYPE_IP != etype) && (ETHERTYPE_IPV6 != etype))
    return 0;

  if (ETHERTYPE_IPV6 == etype)
    return (handle_ipv6 ((struct ip6_hdr *) pkt, len));
  else
    return handle_ip((struct ip *) pkt, len);
}
#endif /* DLT_LINUX_SLL */

	
/*
* Public function that handle the packet doing different operations depending on the type of the packet
*/
void handle_pcap(u_char *udata, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
  
  DEBUG("DBGHTTP * * * New packet with lenght %d",hdr->caplen);
  int status;
  
   
  
  if (hdr->caplen < ETHER_HDR_LEN)
    return;

  switch (pcap_datalink (pcap_obj))
  {
    case DLT_EN10MB:
    status = handle_ether (pkt, hdr->caplen);
    break;
  #if HAVE_NET_IF_PPP_H
    case DLT_PPP:
    status = handle_ppp (pkt, hdr->caplen);
    break;
  #endif
  #ifdef DLT_LOOP
    case DLT_LOOP:
    status = handle_loop (pkt, hdr->caplen);
    break;
  #endif
  #ifdef DLT_RAW
    case DLT_RAW:
    status = handle_raw (pkt, hdr->caplen);
    break;
  #endif
  #ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
    status = handle_linux_sll (pkt, hdr->caplen);
    break;
  #endif
    case DLT_NULL:
    status = handle_null (pkt, hdr->caplen);
    break;

    default:
      ERROR ("handle_pcap: unsupported data link type %d",
      pcap_datalink(pcap_obj));
      status = 0;
      break;
  } /* switch (pcap_datalink(pcap_obj)) */

    if (0 == status)
    return;

    query_count_intvl++;
    query_count_total++;
    last_ts = hdr->ts;
}
#endif /* HAVE_PCAP_H */

/*
* return the string corresponding to the input mime type 
*/
const char *mime_str(int m)
{
  switch(m)
  {
    case MIME_APPLICATION: 	return ("application");
    case MIME_AUDIO: 		return ("audio");
    case MIME_EXAMPLE: 		return ("example");
    case MIME_IMAGE: 		return ("image");
    case MIME_MESSAGE: 		return ("message");
    case MIME_MODEL: 		return ("model");
    case MIME_MULTIPART: 	return ("multipart");
    case MIME_TEXT: 		return ("text");
    case MIME_VIDEO:		return ("video");
    default:
      ERROR("DBGHTTP HTTP plugin error: invalid input on rm_str function");
      return ("OTHER");
  }
}
	    
/*
* return the string corresponding to the input request method type
*/
const char *rm_str(int r)
{
  switch(r)
  {
    case RM_OPTIONS: 		return ("OPTIONS");
    case RM_GET: 		return ("GET");
    case RM_HEAD: 		return ("HEAD");
    case RM_POST: 		return ("POST");
    case RM_PUT: 		return ("PUT");
    case RM_DELETE: 		return ("DELETE");
    case RM_TRACE: 		return ("TRACE");
    case RM_CONNECT: 		return ("CONNECT");
    default:
      ERROR("HTTP plugin error: invalid input on rm_str function");
      return ("OTHER");
  }
}

/*
* return the string corresponding to the input status code type
*/
const char *sc_str(int s)
{
  switch(s)
  {
    case SC_100:	return ("100");
    case SC_101:	return ("101");
    case SC_200:	return ("200");
    case SC_201:	return ("201");
    case SC_202:	return ("202");
    case SC_203:	return ("203");
    case SC_204:	return ("204");
    case SC_205:	return ("205");
    case SC_206:	return ("206");
    case SC_300:	return ("300");
    case SC_301:	return ("301");
    case SC_302:	return ("302");
    case SC_303:	return ("303");
    case SC_304:	return ("304");
    case SC_305:	return ("305");
    case SC_306:	return ("306");
    case SC_307:	return ("307");
    case SC_400:	return ("400");
    case SC_401:	return ("401");
    case SC_402:	return ("402");
    case SC_403:	return ("403");
    case SC_404:	return ("404");
    case SC_405:	return ("405");
    case SC_406:	return ("406");
    case SC_407:	return ("407");
    case SC_408:	return ("408");
    case SC_409:	return ("409");
    case SC_410:	return ("410");
    case SC_411:	return ("411");
    case SC_412:	return ("412");
    case SC_413:	return ("413");
    case SC_414:	return ("414");
    case SC_415:	return ("415");
    case SC_416:	return ("416");
    case SC_417:	return ("417");
    case SC_500:	return ("500");
    case SC_501:	return ("501");
    case SC_502:	return ("502");
    case SC_503:	return ("503");
    case SC_504:	return ("504");
    case SC_505:	return ("505");
    default:
      ERROR("DBGHTTP HTTP plugin error: invalid input on sc_str function");
      return ("OTHER");
  }
}
