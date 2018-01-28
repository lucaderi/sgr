/*
 * clasnif.c - a jpeg sniffer
 * Author: Claudio Santini (santinic@cli.di.unipi.it)
 */

#include <pcap.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>

#include "uthash.h"
#include "clasnif.h"

/* #define DEBUG */
#define FILTER 	"tcp port 80"
#define MAX_CONNECTIONS 256
#define MAX_LEN 65535
#define TIMEOUT_CHECK 10 /* every TIMEOUT_CHECK packets we look for dead connections */
#define TIMEOUT 5 /* after TIMEOUT seconds a connection is deleted from the hashmap */

u_char jpeg_soi[] = { 0xFF, 0xD8 };						/* Jpeg image start */
u_char jpeg_eoi[] = { 0xFF, 0xD9 };						/* Jpeg image end */
u_char http_header_end[] = { 0x0d, 0x0a, 0x0d, 0x0a };	/* CRLF (\r\n\r\n) */

conn_t * connections = NULL;						/* The hash table, see uthash.h */
int packet_offset = sizeof(struct ether_header); 	/* ip packet offset */
int counter = 0;									/* number of found images */
int packets = 1;
int timeout_counter = 1;
int datalink;

void hex(char *buf, int size)
{
#ifdef DEBUG
  if(size < 4) return;
  fprintf(stderr, ">> %x %x ... %x %x\n", (u_char)buf[0], (u_char)buf[1],
	  (u_char)buf[size-2], (u_char)buf[size-1]);
#endif
}

/* Print only if DEBUG is defined */
inline int mlog(char * fmt, ...)
{
#ifdef DEBUG
  int r;
  va_list l;
  va_start(l, fmt);
  r = vfprintf(stderr, fmt, l);
  va_end(l);
  return r;
#else
  return 0;
#endif
}

void save_image_list(list_t * list)
{
  FILE *file;
  char filename[256];

  sprintf(filename, "%d.jpg", counter);
  file = fopen(filename, "w");
  if(file == NULL) {
    perror("Can't open file");
    exit(EXIT_FAILURE);
  }
  while(list != NULL) {
    fwrite(list->buf, 1, list->size, file);
    list = (list_t*)list->next;
  }
  fclose(file);
  counter++;
}

/* Deallocate conection buffers */
void conn_free(conn_t * c)
{
  list_t * list, * tmp;

  if(c == NULL || c->head == NULL) return;
  for(list = c->head; list != NULL; ) {
    tmp = list;
    list = (list_t*)list->next;
    free(tmp->start);
    free(tmp);
  }
  free(c);
}

/* Deallocate dead connections */
void check_dead_connections()
{
  conn_t * c, * tmp;
  time_t now;
  double diff;

  time(&now);

  if(connections == NULL) return;
  for(c = connections; c != NULL; ) {
    diff = (time_t)(now - c->time);
    if(diff >= TIMEOUT) {
      mlog("### now=%d c->time=%d diff=%f\n", (int)now, (int)c->time, diff);
      mlog("### deleted for timeout\n");
      tmp = c->hh.next;
      HASH_DEL(connections, c);
      conn_free(c);
      c = tmp;
    }
    else {
      c = c->hh.next;
    }
  }
}

/* Finds substring needle in haystack with the Boyer-Moore-Horspool algorithm */
static unsigned char * memstr(const unsigned char *haystack, const size_t hlen,
			      const unsigned char *needle, const size_t nlen)
{
  int skip[256], k=0;
  if (nlen == 0) return (unsigned char*)haystack;

  for(k=0; k < 255; ++k) skip[k] = nlen;
  for(k=0; k < nlen - 1; ++k) skip[needle[k]] = nlen - k - 1;

  for(k = nlen - 1; k < hlen; k += skip[haystack[k]]) {
    int i, j;
    for(j = nlen - 1, i = k; j >= 0 && haystack[i] == needle[j]; j--) i--;
    if(j == -1) return (unsigned char*)(haystack + i + 1);
  }
  return NULL;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ether_header *ether;			/* ethernet header */
  struct ip *ip;						/* ip header */
  struct tcphdr *tcp;					/* tcp header */
  int off;
  int hlen;							/* lenght of the header (eth + ip + tcp)*/
  int datalen;						/* length of packet data */
  int size;
  conn_t *conn;						/* generic connection struct */
  list_t *list, *new;
  unsigned char *start, *end, *data;	/* memstr return value */
  hashkey_t key;						/* key for the hasmap */

#ifdef DEBUG
  mlog("packet %d\n", packets);
  packets++;
#endif

  timeout_counter++;
  if(timeout_counter == TIMEOUT_CHECK) {
    check_dead_connections();
    timeout_counter = 1;
  }

  off = ((113 == datalink) ? 2 : 0);
  ether = (struct ether_header*)(packet+off);
  if(ntohs(ether->ether_type) == ETHERTYPE_IP) {
    hlen = sizeof(struct ether_header) + off;
    ip = (struct ip*)(packet + hlen);
    hlen += sizeof(struct ip);
    tcp = (struct tcphdr*) (packet + hlen);
    hlen = hlen + (tcp->doff << 2);
    datalen = header->len - hlen;

    if(datalen < 80) {
      /* This is not for sure an HTTP packet with interesting data */
      mlog("----------------------------------\n");
      return;
    }

    mlog("ether: "); hex((char*)ether, sizeof(struct ether_header));
    mlog("ip: "); 	hex((char*)ip, sizeof(struct ip));
    mlog("tcp: ");	hex((char*)tcp, sizeof(struct tcphdr));
    mlog("header->len=%d hlen=%d datalen=%d\n", header->len, hlen, datalen);

    if(datalen > 0) {
      data = (unsigned char*)malloc(datalen);
      if (data == NULL) {
	perror("Cannot alloc memory");
	exit(EXIT_FAILURE);
      }
      memcpy(data, packet + hlen, datalen);
      mlog("data: ");	hex((char*)data, datalen);
      /* Generate the key for the hashmap */
      key.src = ip->ip_src;
      key.dst = ip->ip_dst;
      key.src_port = tcp->source;
      key.dst_port = tcp->dest;
      HASH_FIND(hh, connections, &key, sizeof(hashkey_t), conn);
      if(conn == NULL) {
	/* If we find jpeg starting bytes we create a new connection */
	start = memstr(data, datalen, jpeg_soi, 2);
	if(start != NULL) {
	  conn = (conn_t*)malloc(sizeof(conn_t));

	  if(data[datalen-2] == jpeg_eoi[0] && data[datalen-1] == jpeg_eoi[1]) {
	    /* All the (little) image is contained in one segment */
	    mlog("tutta l'immagine in un segmento\n");
	    conn->head = (list_t*)malloc(sizeof(list_t));
	    if(conn->head == NULL) {
	      perror("Cannot alloc memory");
	      exit(EXIT_FAILURE);
	    }
	    memcpy(&conn->key, &key, sizeof(hashkey_t));
	    conn->head->size = data+datalen - start;
	    conn->head->buf = start;
	    conn->head->next = NULL;
	    conn->head->start = data;
	    time(&(conn->time));
	    save_image_list(conn->head);
	    fprintf(stderr, "Image saved in %d.jpg\n", counter-1);
	    conn_free(conn);
	  }
	  else {
	    memcpy(&conn->key, &key, sizeof(hashkey_t));
	    HASH_ADD(hh, connections, key, sizeof(hashkey_t), conn);
	    conn->head = (list_t*)malloc(sizeof(list_t));
	    if(conn->head == NULL) {
	      perror("Cannot alloc memory");
	      exit(EXIT_FAILURE);
	    }
	    conn->head->next = NULL;
	    conn->head->buf = start;
	    conn->head->start = data;
	    conn->head->size = data+datalen - start;
	    mlog( "salvo: ");
	    hex((char*)conn->head->buf, conn->head->size);
	    time(&(conn->time));
	  }
	}
      }
      else {
	start = memstr(data, datalen, http_header_end, sizeof(http_header_end));
	if(start != NULL) {
	  mlog("http header end found at %d\n", (int)start);
	  start += sizeof(http_header_end);
	}
	else {
	  start = data;
	}

	end = memstr(data, datalen, jpeg_eoi, 2);
	end += 2; /* jpeg_eoi bytes */

	/* If jpeg_eoi bytes are not the end of the segment, then
	 * "end" is not the real end of the image */
	if(end == NULL || data+datalen != end) {
	  /* If we don't find the end of the image we continue storing
	   * untill MAX_IMAGE bytes */
	  mlog("C'è la connesione ma non l'eoi size=%d\n", datalen);
	  /* Go through the list untill the end */
	  list = conn->head;
	  while(list->next != NULL) {
	    list = (list_t*)list->next;
	  }
	  new = (list_t*)malloc(sizeof(list_t));
	  list->next = (struct list_t*)new;
	  new->buf = start;
	  new->start = data;
	  new->size = data+datalen - start;
	  mlog("salvo in lista: ");
	  hex((char*)new->buf, new->size);
	  time(&(conn->time));
	  new->next = NULL;
	}
	else {
	  mlog("fine dell'immagine data=%d end=%d data+datalen=%d\n", (int)data, (int)end, (int)(data+datalen));
	  list = conn->head;
	  while(list->next != NULL) {
	    list = (list_t*)list->next;
	  }
	  new = (list_t*)malloc(sizeof(list_t));
	  if(new == NULL) {
	    perror("Cannot alloc memory");
	    exit(EXIT_FAILURE);
	  }
	  size = end - start;
	  new->buf = (u_char*)malloc(size);
	  new->start = new->buf;
	  if(new->buf == NULL) {
	    perror("Cannot alloc memory");
	    exit(EXIT_FAILURE);
	  }
	  memcpy(new->buf, data, size);
	  free(data);
	  new->size = size;
	  new->next = NULL;
	  list->next = (struct list_t*)new;
	  save_image_list(conn->head);
	  printf("Image saved in %d.jpg\n", counter-1);
	  HASH_DEL(connections, conn);
	  conn_free(conn);
	}
      }
    }
  }
  mlog("----------------------------------\n");
}

int main(int argc, char *argv[])
{
  char *dev;								/* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];			/* Error string */
  pcap_t *handle;							/* Session handle */
  struct bpf_program filter;				/* The compiled filter */

  if(argc > 1) {
    dev = argv[1];
  }
  else {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(2);
    }
  }
  printf("Device: %s\n", dev);
  handle = pcap_open_live(dev, MAX_LEN, 0, 10000, errbuf);
  if(handle == NULL) {
    if(getuid() != 0)
      fprintf(stderr, "Perhaps you need to be root?\n");
    else
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }
  if(pcap_compile(handle, &filter, FILTER, 1, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER,
	    pcap_geterr(handle));
    return (2);
  }
  if(pcap_setfilter(handle, &filter) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER,
	    pcap_geterr(handle));
    return (2);
  }
  datalink = pcap_datalink(handle);
  pcap_loop(handle, -1, process_packet, NULL);
  return(0);
}
