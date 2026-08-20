#include "dhcp_parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>   /* struct ether_header, ETHERTYPE_IP */
#include <netinet/ip.h>     /* struct ip */

/* ---- Minimal UDP header (avoids platform differences in field names) -- */
struct udp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
};

#define DHCP_SERVER_PORT  67
#define DHCP_CLIENT_PORT  68

typedef struct {
  dhcp_capture_handler handler;
  void *user;
} dhcp_capture_cb_t;

static void capture_set_error(char *errbuf, size_t errbuf_len,
                              const char *fmt, ...)
{
  va_list ap;

  if (!errbuf || errbuf_len == 0)
    return;

  va_start(ap, fmt);
  vsnprintf(errbuf, errbuf_len, fmt, ap);
  va_end(ap);
}

static void capture_raw_packet(u_char *user,
                               const struct pcap_pkthdr *hdr,
                               const u_char *pkt)
{
  dhcp_capture_cb_t *ctx = (dhcp_capture_cb_t *)user;
  dhcp_info_t info;

  if (!ctx || !ctx->handler)
    return;

  if (dhcp_parse(hdr, pkt, &info) != 0)
    return;

  ctx->handler(&info, ctx->user);
}

int dhcp_capture_open(dhcp_capture_t *capture,
                      const char *iface,
                      int snaplen,
                      int promiscuous,
                      int timeout_ms,
                      const char *bpf_filter,
                      int nonblock,
                      char *errbuf,
                      size_t errbuf_len)
{
  char pcap_err[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  if (!capture || !iface || !*iface || !bpf_filter || !*bpf_filter) {
    capture_set_error(errbuf, errbuf_len,
                      "dhcp_capture_open: invalid capture arguments");
    return -1;
  }

  capture->handle = NULL;
  pcap_err[0] = '\0';

  capture->handle = pcap_open_live(iface, snaplen, promiscuous, timeout_ms,
                                   pcap_err);
  if (!capture->handle) {
    capture_set_error(errbuf, errbuf_len, "pcap_open_live: %s", pcap_err);
    return -1;
  }

  if (pcap_compile(capture->handle, &fp, bpf_filter, 1,
                   PCAP_NETMASK_UNKNOWN) < 0) {
    capture_set_error(errbuf, errbuf_len, "pcap_compile: %s",
                      pcap_geterr(capture->handle));
    pcap_close(capture->handle);
    capture->handle = NULL;
    return -1;
  }

  if (pcap_setfilter(capture->handle, &fp) < 0) {
    capture_set_error(errbuf, errbuf_len, "pcap_setfilter: %s",
                      pcap_geterr(capture->handle));
    pcap_freecode(&fp);
    pcap_close(capture->handle);
    capture->handle = NULL;
    return -1;
  }
  pcap_freecode(&fp);

  if (nonblock && pcap_setnonblock(capture->handle, 1, pcap_err) < 0) {
    capture_set_error(errbuf, errbuf_len, "pcap_setnonblock: %s", pcap_err);
    pcap_close(capture->handle);
    capture->handle = NULL;
    return -1;
  }

  return 0;
}

int dhcp_capture_dispatch(dhcp_capture_t *capture,
                          int batch,
                          dhcp_capture_handler handler,
                          void *user,
                          char *errbuf,
                          size_t errbuf_len)
{
  dhcp_capture_cb_t cb;
  int rc;

  if (!capture || !capture->handle || !handler) {
    capture_set_error(errbuf, errbuf_len,
                      "dhcp_capture_dispatch: capture is not open");
    return DHCP_CAPTURE_ERROR;
  }

  cb.handler = handler;
  cb.user = user;

  rc = pcap_dispatch(capture->handle, batch, capture_raw_packet,
                     (u_char *)&cb);
  if (rc == PCAP_ERROR_BREAK)
    return DHCP_CAPTURE_BREAK;
  if (rc == PCAP_ERROR) {
    capture_set_error(errbuf, errbuf_len, "pcap_dispatch: %s",
                      pcap_geterr(capture->handle));
    return DHCP_CAPTURE_ERROR;
  }

  return rc;
}

int dhcp_capture_loop(dhcp_capture_t *capture,
                      dhcp_capture_handler handler,
                      void *user,
                      char *errbuf,
                      size_t errbuf_len)
{
  dhcp_capture_cb_t cb;
  int rc;

  if (!capture || !capture->handle || !handler) {
    capture_set_error(errbuf, errbuf_len,
                      "dhcp_capture_loop: capture is not open");
    return DHCP_CAPTURE_ERROR;
  }

  cb.handler = handler;
  cb.user = user;

  rc = pcap_loop(capture->handle, 0, capture_raw_packet, (u_char *)&cb);
  if (rc == PCAP_ERROR_BREAK)
    return DHCP_CAPTURE_BREAK;
  if (rc == PCAP_ERROR) {
    capture_set_error(errbuf, errbuf_len, "pcap_loop: %s",
                      pcap_geterr(capture->handle));
    return DHCP_CAPTURE_ERROR;
  }

  return rc;
}

void dhcp_capture_breakloop(dhcp_capture_t *capture)
{
  if (capture && capture->handle)
    pcap_breakloop(capture->handle);
}

void dhcp_capture_close(dhcp_capture_t *capture)
{
  if (!capture || !capture->handle)
    return;

  pcap_close(capture->handle);
  capture->handle = NULL;
}

/* ---- dhcp_parse ------------------------------------------------------- */
int dhcp_parse(const struct pcap_pkthdr *hdr,
               const u_char *pkt,
               dhcp_info_t *out)
{
  const struct ether_header *eth;
  const struct ip           *ip_hdr;
  const struct udp_hdr      *udp;
  const struct dhcp_pkt     *dhcp;
  size_t caplen;
  size_t eth_len;
  size_t ip_payload_available;
  unsigned int ip_hdr_len;
  uint16_t ip_total_len;
  uint16_t udp_len;
  uint16_t sport, dport;
  const uint8_t *opts;
  int opts_len;
  size_t i;

  if (!hdr || !pkt || !out)
    return -1;

  caplen = hdr->caplen;
  eth_len = sizeof(struct ether_header);

  /* --- Ethernet -------------------------------------------------------- */
  if (caplen < eth_len + sizeof(struct ip))
    return -1;

  eth = (const struct ether_header *)pkt;

  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return -1;

  /* --- IP -------------------------------------------------------------- */
  ip_hdr = (const struct ip *)(pkt + sizeof(struct ether_header));

  if (ip_hdr->ip_p != IPPROTO_UDP)
    return -1;

  ip_hdr_len = ip_hdr->ip_hl * 4;
  if (ip_hdr_len < sizeof(struct ip))
    return -1;

  if (caplen < eth_len + ip_hdr_len + sizeof(struct udp_hdr))
    return -1;

  ip_total_len = ntohs(ip_hdr->ip_len);
  if (ip_total_len < ip_hdr_len + sizeof(struct udp_hdr) + DHCP_FIXED_LEN)
    return -1;

  ip_payload_available = caplen - eth_len - ip_hdr_len;

  /* --- UDP ------------------------------------------------------------- */
  udp   = (const struct udp_hdr *)((const uint8_t *)ip_hdr + ip_hdr_len);
  sport = ntohs(udp->sport);
  dport = ntohs(udp->dport);
  udp_len = ntohs(udp->len);

  if (!((sport == DHCP_CLIENT_PORT && dport == DHCP_SERVER_PORT) ||
        (sport == DHCP_SERVER_PORT && dport == DHCP_CLIENT_PORT)))
    return -1;

  if (udp_len < sizeof(struct udp_hdr) + DHCP_FIXED_LEN)
    return -1;
  if (udp_len > ip_payload_available)
    return -1;
  if (udp_len > ip_total_len - ip_hdr_len)
    return -1;

  /* --- DHCP ------------------------------------------------------------ */
  dhcp = (const struct dhcp_pkt *)((const uint8_t *)udp + sizeof(struct udp_hdr));

  if (ntohl(dhcp->magic_cookie) != DHCP_MAGIC_COOKIE)
    return -1;

  /* --- Fill output struct --------------------------------------------- */
  memset(out, 0, sizeof(*out));

  out->ts     = hdr->ts;
  out->xid    = ntohl(dhcp->xid);
  out->src_ip = ip_hdr->ip_src;
  out->dst_ip = ip_hdr->ip_dst;
  memcpy(&out->ciaddr, &dhcp->ciaddr, 4);
  memcpy(&out->yiaddr, &dhcp->yiaddr, 4);
  memcpy(out->eth_src, eth->ether_shost, 6);
  memcpy(out->mac, dhcp->chaddr, 6);

  /* --- Scan options for message type (option 53) ---------------------- */
  opts = (const uint8_t *)dhcp + DHCP_FIXED_LEN;
  opts_len = (int)(udp_len - sizeof(struct udp_hdr) - DHCP_FIXED_LEN);

  i = 0;
  while (i < (size_t)opts_len) {
    uint8_t opt = opts[i++];

    if (opt == DHCP_OPT_END)  break;
    if (opt == DHCP_OPT_PAD)  continue;

    if (i >= (size_t)opts_len) break;
    uint8_t len = opts[i++];

    if (i + len > (size_t)opts_len) break;

    if (opt == DHCP_OPT_MSGTYPE && len == 1)
      out->msg_type = opts[i];
    else if (opt == DHCP_OPT_REQUESTED_IP && len == 4)
      memcpy(&out->requested_ip, &opts[i], 4);

    i += len;
  }

  return 0;
}

/* ---- dhcp_msgtype_str ------------------------------------------------- */
const char *dhcp_msgtype_str(uint8_t msg_type)
{
  switch (msg_type) {
    case DHCP_DISCOVER: return "DISCOVER";
    case DHCP_OFFER:    return "OFFER";
    case DHCP_REQUEST:  return "REQUEST";
    case DHCP_DECLINE:  return "DECLINE";
    case DHCP_ACK:      return "ACK";
    case DHCP_NAK:      return "NAK";
    case DHCP_RELEASE:  return "RELEASE";
    case DHCP_INFORM:   return "INFORM";
    default:            return "UNKNOWN";
  }
}
