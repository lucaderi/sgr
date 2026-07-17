#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../config/defense_config.h"
#include "dhcp_parser.h"

static dhcp_capture_t capture;

static int load_test_config(const char *path)
{
  const char *env_path;

  if (path && *path)
    return cfg_load(path);

  env_path = getenv(DEFENSE_CONFIG_ENV);
  if (env_path && *env_path)
    return cfg_load(env_path);

  if (access(DEFENSE_CONFIG_DEFAULT_PATH, R_OK) == 0)
    return cfg_load(DEFENSE_CONFIG_DEFAULT_PATH);
  if (access(DEFENSE_CONFIG_PROJECT_PATH, R_OK) == 0)
    return cfg_load(DEFENSE_CONFIG_PROJECT_PATH);
  if (access("../" DEFENSE_CONFIG_PROJECT_PATH, R_OK) == 0)
    return cfg_load("../" DEFENSE_CONFIG_PROJECT_PATH);

  fprintf(stderr,
          "[WARN] [test_parser] config file not found; using compiled defaults "
          "and environment overrides.\n");
  cfg_use_defaults(".");
  return 0;
}

static void handle_signal(int sig)
{
  (void)sig;
  dhcp_capture_breakloop(&capture);
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t len)
{
  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ip_to_str(const struct in_addr *addr, char *buf, size_t len,
                      const char *label)
{
  if (inet_ntop(AF_INET, addr, buf, len))
    return;

  snprintf(buf, len, "invalid");
  fprintf(stderr,
          "[WARN] [test_parser] failed to format %s IPv4 address\n",
          label);
}

/* ---- parsed DHCP callback -------------------------------------------- */
static void got_packet(const dhcp_info_t *info, void *user)
{
  char mac_str[18], eth_src_str[18];
  char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
  char ci_str[INET_ADDRSTRLEN],  yi_str[INET_ADDRSTRLEN];
  char req_str[INET_ADDRSTRLEN];

  (void)user;

  if (!info)
    return;

  mac_to_str(info->mac, mac_str, sizeof(mac_str));
  mac_to_str(info->eth_src, eth_src_str, sizeof(eth_src_str));

  ip_to_str(&info->src_ip, src_str, sizeof(src_str), "source");
  ip_to_str(&info->dst_ip, dst_str, sizeof(dst_str), "destination");
  ip_to_str(&info->ciaddr, ci_str, sizeof(ci_str), "ciaddr");
  ip_to_str(&info->yiaddr, yi_str, sizeof(yi_str), "yiaddr");
  ip_to_str(&info->requested_ip, req_str, sizeof(req_str), "requested");

  printf("[%ld.%06ld]  %-9s  xid=%08x  eth_src=%s  chaddr=%s  %s -> %s",
         (long)info->ts.tv_sec,
         (long)info->ts.tv_usec,
         dhcp_msgtype_str(info->msg_type),
         info->xid,
         eth_src_str,
         mac_str,
         src_str,
         dst_str);

  if (info->ciaddr.s_addr != 0)
    printf("  ciaddr=%s", ci_str);
  if (info->yiaddr.s_addr != 0)
    printf("  yiaddr=%s", yi_str);
  if (info->requested_ip.s_addr != 0)
    printf("  requested=%s", req_str);

  printf("\n");
}

static void usage(const char *prog)
{
  fprintf(stderr,
      "usage: %s [--config FILE] <interface>\n"
      "\n"
      "  Standalone real-time test for the DHCP parser module.\n"
      "  It opens a libpcap capture through dhcp_parser/, installs the\n"
      "  configured BPF filter, parses DHCP packets, and prints one line\n"
      "  for each valid DHCP message. It does not run detection, reputation,\n"
      "  mitigation, or RRD logic.\n"
      "\n"
      "  Output fields include both Ethernet source MAC and DHCP chaddr.\n"
      "  This makes Ethernet/DHCP MAC mismatch traffic visible while testing\n"
      "  the parser.\n"
      "\n"
      "options:\n"
      "  --config FILE  optional YAML config path; if omitted, the test uses\n"
      "                 DHCP_DEFENSE_CONFIG, config/config.yaml, the project\n"
      "                 default config path, or compiled defaults as fallback\n"
      "\n"
      "arguments:\n"
      "  interface  network interface to monitor, for example ens160 or eth0\n"
      "\n"
      "examples:\n"
      "  sudo %s ens160\n"
      "  sudo %s --config src/defense/dhcp_starvation_detector/config/config.yaml eth0\n",
      prog, prog, prog);
}

/* ---- main ------------------------------------------------------------- */
int main(int argc, char *argv[])
{
  char errbuf[DHCP_CAPTURE_ERRBUF_SIZE];
  const char *config_path = NULL;
  const char *dev;
  const char *filter;
  int rc;
  int exit_status = EXIT_SUCCESS;

  dev = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 ||
        strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return EXIT_SUCCESS;
    }
    if (strcmp(argv[i], "--config") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "[FAIL] [test_parser] --config requires a value\n");
        usage(argv[0]);
        return EXIT_FAILURE;
      }
      config_path = argv[i];
      continue;
    }
    if (argv[i][0] == '-') {
      fprintf(stderr, "[FAIL] [test_parser] unknown argument: %s\n", argv[i]);
      usage(argv[0]);
      return EXIT_FAILURE;
    }
    if (dev) {
      fprintf(stderr, "[FAIL] [test_parser] too many positional arguments\n");
      usage(argv[0]);
      return EXIT_FAILURE;
    }
    dev = argv[i];
  }

  if (!dev) {
    fprintf(stderr, "[FAIL] [test_parser] missing interface\n");
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (load_test_config(config_path) != 0)
    return EXIT_FAILURE;

  filter = cfg_get_string("pcap.dhcp_filter",
                          "udp and (port 67 or port 68)");

  if (dhcp_capture_open(&capture,
                        dev,
                        cfg_get_int("pcap.snaplen", 65535),
                        cfg_get_int("pcap.promiscuous", 1),
                        cfg_get_int("pcap.timeout_ms", 100),
                        filter,
                        0,
                        errbuf,
                        sizeof(errbuf)) != 0) {
    fprintf(stderr, "[FAIL] [test_parser] %s\n", errbuf);
    return EXIT_FAILURE;
  }

  signal(SIGINT,  handle_signal);
  signal(SIGTERM, handle_signal);

  printf("[test_parser] interface: %s\n", dev);
  printf("[test_parser] config   : %s\n", cfg_loaded_path());
  printf("[test_parser] filter   : \"%s\"\n\n", filter);
  printf("%-19s  %-9s  %-12s  %-27s  %-27s  %s\n",
         "timestamp", "type", "xid", "eth_src", "chaddr", "src -> dst");
  printf("-------------------  ---------  ------------  ---------------------------  ---------------------------  ---\n");

  rc = dhcp_capture_loop(&capture, got_packet, NULL, errbuf, sizeof(errbuf));
  if (rc == DHCP_CAPTURE_ERROR) {
    fprintf(stderr, "[FAIL] [test_parser] %s\n", errbuf);
    exit_status = EXIT_FAILURE;
  }

  dhcp_capture_close(&capture);
  return exit_status;
}
