#ifndef DHCP_PARSER_H
#define DHCP_PARSER_H

#include <pcap.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

/* ---- DHCP message types (option 53) ---------------------------------- */
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NAK        6
#define DHCP_RELEASE    7
#define DHCP_INFORM     8

/* ---- BOOTP/DHCP wire layout (fixed header, 240 bytes) ---------------- */
#define DHCP_MAGIC_COOKIE   0x63825363U
#define DHCP_FIXED_LEN      240         /* 236 BOOTP + 4 magic cookie */

struct dhcp_pkt {
  uint8_t   op;           /* 1 = request, 2 = reply */
  uint8_t   htype;        /* hardware type (1 = Ethernet) */
  uint8_t   hlen;         /* hardware address length */
  uint8_t   hops;
  uint32_t  xid;          /* transaction ID */
  uint16_t  secs;
  uint16_t  flags;
  uint32_t  ciaddr;       /* client IP (already has one) */
  uint32_t  yiaddr;       /* 'your' IP (server offer) */
  uint32_t  siaddr;       /* next server IP */
  uint32_t  giaddr;       /* relay agent IP */
  uint8_t   chaddr[16];   /* client hardware address (MAC in first 6 bytes) */
  uint8_t   sname[64];
  uint8_t   file[128];
  uint32_t  magic_cookie;
  /* options follow immediately after, variable length */
} __attribute__((packed));

/* ---- DHCP options ---------------------------------------------------- */
#define DHCP_OPT_PAD        0
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_MSGTYPE    53
#define DHCP_OPT_END        255

#define DHCP_CAPTURE_ERRBUF_SIZE PCAP_ERRBUF_SIZE
#define DHCP_CAPTURE_ERROR       (-1)
#define DHCP_CAPTURE_BREAK       (-2)

/* ---- Parsed output --------------------------------------------------- */
typedef struct {
  struct timeval ts;       /* packet timestamp */
  uint8_t  msg_type;       /* value from option 53, 0 if absent */
  uint8_t  eth_src[6];     /* Ethernet source MAC */
  uint8_t  mac[6];         /* client hardware address */
  uint32_t xid;            /* transaction ID */
  struct in_addr src_ip;   /* IP-level source */
  struct in_addr dst_ip;   /* IP-level destination */
  struct in_addr ciaddr;   /* client IP (network byte order) */
  struct in_addr yiaddr;   /* offered IP (network byte order) */
  struct in_addr requested_ip; /* option 50, requested IP address */
} dhcp_info_t;

/* ---- Capture session ------------------------------------------------- */
typedef struct {
  void *handle;
} dhcp_capture_t;

typedef void (*dhcp_capture_handler)(const dhcp_info_t *info, void *user);

/* ---- Public API ------------------------------------------------------ */

/* Parse a raw pcap packet.
 * Returns 0 on success, -1 if the packet is not a valid DHCP message. */
int dhcp_parse(const struct pcap_pkthdr *hdr,
               const u_char *pkt,
               dhcp_info_t *out);

/* Open a capture session, install the BPF filter, and optionally enable
 * non-blocking mode.
 * Returns 0 on success, -1 on error. */
int dhcp_capture_open(dhcp_capture_t *capture,
                      const char *iface,
                      int snaplen,
                      int promiscuous,
                      int timeout_ms,
                      const char *bpf_filter,
                      int nonblock,
                      char *errbuf,
                      size_t errbuf_len);

/* Dispatch packets and deliver only parsed DHCP messages to handler.
 * Returns the pcap dispatch count, DHCP_CAPTURE_BREAK, or DHCP_CAPTURE_ERROR. */
int dhcp_capture_dispatch(dhcp_capture_t *capture,
                          int batch,
                          dhcp_capture_handler handler,
                          void *user,
                          char *errbuf,
                          size_t errbuf_len);

/* Blocking capture loop variant used by simple manual tools. */
int dhcp_capture_loop(dhcp_capture_t *capture,
                      dhcp_capture_handler handler,
                      void *user,
                      char *errbuf,
                      size_t errbuf_len);

void dhcp_capture_breakloop(dhcp_capture_t *capture);
void dhcp_capture_close(dhcp_capture_t *capture);

/* Return a human-readable name for a DHCP message type. */
const char *dhcp_msgtype_str(uint8_t msg_type);

#endif /* DHCP_PARSER_H */
