#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../config/defense_config.h"
#include "../dhcp_parser/dhcp_parser.h"
#include "mac_reputation.h"

static mac_reputation_t mr;
static dhcp_capture_t capture;
static volatile sig_atomic_t stop_requested = 0;

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
            "[WARN] [test_reputation] config file not found; using compiled defaults and "
            "environment overrides.\n");
    cfg_use_defaults(".");
    return 0;
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int ip_to_str(uint32_t ip, char *buf, size_t len, const char *label)
{
    struct in_addr a = { .s_addr = ip };

    if (inet_ntop(AF_INET, &a, buf, len))
        return 0;

    snprintf(buf, len, "invalid");
    fprintf(stderr,
            "[WARN] [test_reputation] failed to format %s IPv4 address\n",
            label);
    return -1;
}

static void on_promote(const uint8_t mac[6], void *ctx)
{
    mac_reputation_t *mr_ctx = ctx;
    char mac_str[18];
    int rc;

    mac_to_str(mac, mac_str, sizeof(mac_str));

    rc = whitelist_add(&mr_ctx->confirmed_wl, mac, "reputation-temporary");
    if (rc < 0) {
        printf("[FAIL] [test_reputation] callback: failed to add temporary whitelist entry %s\n",
               mac_str);
        return;
    }

    printf("[test_reputation] callback: add temporary whitelist entry %s\n",
           mac_str);
    printf("[test_reputation] callback: NETCONF push simulated only\n");
}

static void on_confirm(const uint8_t mac[6], uint32_t ip, void *ctx)
{
    (void)ctx;
    char mac_str[18];
    char ip_str[INET_ADDRSTRLEN];

    mac_to_str(mac, mac_str, sizeof(mac_str));
    ip_to_str(ip, ip_str, sizeof(ip_str), "confirmed lease");
    printf("[test_reputation] callback: confirm %s ip=%s\n",
           mac_str, ip_str);
}

static void on_reject(const uint8_t mac[6], uint32_t ip, void *ctx)
{
    mac_reputation_t *mr_ctx = ctx;
    char mac_str[18];
    char ip_str[INET_ADDRSTRLEN];
    int rc;

    mac_to_str(mac, mac_str, sizeof(mac_str));
    if (ip != 0)
        ip_to_str(ip, ip_str, sizeof(ip_str), "rejected lease");

    rc = whitelist_remove(&mr_ctx->confirmed_wl, mac);
    printf("[test_reputation] callback: remove/reject %s ip=%s\n",
           mac_str, ip ? ip_str : "none");
    if (rc == 0)
        printf("[test_reputation] callback: removed from whitelist file\n");
    else if (rc == 1)
        printf("[test_reputation] callback: whitelist entry was not present\n");
    else
        printf("[FAIL] [test_reputation] callback: failed to update whitelist file\n");
    printf("[test_reputation] callback: NETCONF push/release simulated only\n");
}

static uint32_t lease_hint_ip(const dhcp_info_t *info)
{
    if (info->yiaddr.s_addr != 0)
        return info->yiaddr.s_addr;
    if (info->requested_ip.s_addr != 0)
        return info->requested_ip.s_addr;
    if (info->ciaddr.s_addr != 0)
        return info->ciaddr.s_addr;
    return 0;
}

static void print_packet(const dhcp_info_t *info, const char *mac_str)
{
    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip = lease_hint_ip(info);

    printf("[test_reputation] packet: DHCP %-8s mac=%s",
           dhcp_msgtype_str(info->msg_type), mac_str);

    if (ip != 0) {
        ip_to_str(ip, ip_str, sizeof(ip_str), "packet lease hint");
        printf(" ip=%s", ip_str);
    }

    printf("\n");
}

static void on_packet(const dhcp_info_t *info, void *user)
{
    (void)user;

    if (!info)
        return;

    char mac_str[18];
    mac_to_str(info->mac, mac_str, sizeof(mac_str));
    print_packet(info, mac_str);

    switch (info->msg_type) {
        case DHCP_DISCOVER:
            if (memcmp(info->eth_src, info->mac, MAC_LEN) != 0) {
                printf("[reputation] %s  ignored  reason=ethernet-src-mismatch\n",
                       mac_str);
                break;
            }
            mr_feed_discover(&mr, info->mac, info->ts.tv_sec);
            break;

        case DHCP_OFFER:
            if (info->yiaddr.s_addr != 0)
                mr_feed_lease_hint(&mr, info->mac, info->yiaddr.s_addr,
                                   info->ts.tv_sec, "OFFER");
            break;

        case DHCP_REQUEST:
            if (info->requested_ip.s_addr != 0)
                mr_feed_lease_hint(&mr, info->mac, info->requested_ip.s_addr,
                                   info->ts.tv_sec, "REQUEST");
            else if (info->ciaddr.s_addr != 0)
                mr_feed_lease_hint(&mr, info->mac, info->ciaddr.s_addr,
                                   info->ts.tv_sec, "REQUEST");
            break;

        case DHCP_ACK:
            mr_feed_ack(&mr, info->mac, lease_hint_ip(info), info->ts.tv_sec);
            break;

        default:
            break;
    }
}

static void on_sigint(int sig)
{
    (void)sig;
    stop_requested = 1;
    dhcp_capture_breakloop(&capture);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--config FILE] <interface> [whitelist_file]\n"
            "\n"
            "  Standalone real-time test for the reputation module.\n"
            "  It captures DHCP packets through dhcp_parser/ and feeds the same\n"
            "  reputation inputs used by the main detector: DISCOVER backoff,\n"
            "  visible OFFER/REQUEST/ACK lease hints, Ethernet/DHCP MAC mismatch\n"
            "  rejection, temporary whitelist callbacks, and ARP confirmation.\n"
            "\n"
            "  State flow:\n"
            "    CANDIDATE -> TRACKING -> READY -> PROVISIONAL -> ARP_PENDING\n"
            "    -> CONFIRMED or REJECTED\n"
            "\n"
            "  CONFIRMED MACs are persisted in the selected whitelist database.\n"
            "  NETCONF push, lease lookup, and lease release are simulated here;\n"
            "  use the main dhcp_starvation_detector for full router mitigation.\n"
            "\n"
            "options:\n"
            "  --config FILE  optional YAML config path; if omitted, the test uses\n"
            "                 DHCP_DEFENSE_CONFIG, config/config.yaml, the project\n"
            "                 default config path, or compiled defaults as fallback\n"
            "\n"
            "arguments:\n"
            "  interface       network interface to monitor and use for ARP probes\n"
            "  whitelist_file  optional whitelist DB path; default: paths.whitelist\n"
            "\n"
            "examples:\n"
            "  sudo %s ens160\n"
            "  sudo %s eth0 db/whitelist.txt\n",
            prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    const char *pos[2];
    int pos_count = 0;
    const char *iface;
    const char *wl_path;
    time_t last_tick = 0;
    int exit_status = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[FAIL] [test_reputation] --config requires a value\n");
                usage(argv[0]);
                return 1;
            }
            config_path = argv[i];
            continue;
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "[FAIL] [test_reputation] unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        if (pos_count >= 2) {
            fprintf(stderr, "[FAIL] [test_reputation] too many positional arguments\n");
            usage(argv[0]);
            return 1;
        }
        pos[pos_count++] = argv[i];
    }

    if (pos_count < 1) {
        fprintf(stderr, "[FAIL] [test_reputation] missing interface\n");
        usage(argv[0]);
        return 1;
    }

    setbuf(stdout, NULL);

    if (load_test_config(config_path) != 0)
        return 1;

    iface = pos[0];
    wl_path = (pos_count >= 2) ? pos[1] : whitelist_cfg_path();

    mr_init(&mr, iface, on_promote, on_confirm, on_reject, &mr);
    if (mr_enable_confirmed_whitelist(&mr, wl_path) != 0) {
        fprintf(stderr,
                "[FAIL] [test_reputation] unable to load whitelist db: %s\n",
                wl_path);
        return 1;
    }

    char errbuf[DHCP_CAPTURE_ERRBUF_SIZE];
    if (dhcp_capture_open(&capture,
                          iface,
                          cfg_get_int("pcap.snaplen", 65535),
                          cfg_get_int("pcap.promiscuous", 1),
                          cfg_get_int("pcap.timeout_ms", 100),
                          cfg_get_string("pcap.dhcp_filter",
                                         "udp and (port 67 or port 68)"),
                          1,
                          errbuf,
                          sizeof(errbuf)) != 0) {
        fprintf(stderr, "[FAIL] [test_reputation] %s\n", errbuf);
        return 1;
    }

    signal(SIGINT, on_sigint);

    printf("[test_reputation] interface : %s\n", iface);
    printf("[test_reputation] config    : %s\n", cfg_loaded_path());
    printf("[test_reputation] whitelist : %s\n", wl_path);
    printf("[test_reputation] min discovers=%d  interval=%d-%ds\n",
           cfg_get_int("reputation.min_discovers", MR_MIN_DISCOVERS),
           cfg_get_int("reputation.min_interval_secs", MR_MIN_INTERVAL_S),
           cfg_get_int("reputation.max_interval_secs", MR_MAX_INTERVAL_S));
    printf("[test_reputation] quotas: tracking=%d  ready=%d  temp-wl=%d\n",
           cfg_get_int("reputation.max_tracking", MR_MAX_TRACKING),
           cfg_get_int("reputation.max_ready", MR_MAX_READY),
           cfg_get_int("reputation.max_temp_whitelist", MR_MAX_TEMP_WL));
    printf("[test_reputation] promotion interval: %ds\n\n",
           cfg_get_int("reputation.promote_interval_secs",
                       MR_PROMOTE_INTERVAL_S));

    while (!stop_requested) {
        int rc = dhcp_capture_dispatch(&capture,
                                       cfg_get_int("pcap.dispatch_batch", 64),
                                       on_packet,
                                       NULL,
                                       errbuf,
                                       sizeof(errbuf));

        if (rc == DHCP_CAPTURE_BREAK)
            break;
        if (rc == DHCP_CAPTURE_ERROR) {
            fprintf(stderr, "[FAIL] [test_reputation] %s\n", errbuf);
            exit_status = 1;
            break;
        }

        time_t now = time(NULL);
        if (now != last_tick) {
            mr_tick(&mr, now);
            last_tick = now;
        }
        usleep((useconds_t)cfg_get_u32("pcap.loop_sleep_us", 100000u));
    }

    dhcp_capture_close(&capture);
    printf("\n[test_reputation] stop.\n");
    return exit_status;
}
