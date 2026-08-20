#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../config/defense_config.h"
#include "../dhcp_parser/dhcp_parser.h"
#include "../netconf_action/netconf_action.h"
#include "detector.h"

/* ~350 KB: keep it off the stack. */
static detector_t            det;
static volatile sig_atomic_t stop_requested = 0;
static dhcp_capture_t        capture;
static netconf_cfg_t         pool_cfg;
static int                   pool_netconf_enabled = 0;

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
            "[WARN] [test_detector] config file not found; using compiled defaults and "
            "environment overrides.\n");
    cfg_use_defaults(".");
    return 0;
}

/* ---- parsed DHCP callback ------------------------------------------------ */

static void on_packet(const dhcp_info_t *info, void *user)
{
    (void)user;

    if (!info)
        return;

    if (info->msg_type == DHCP_DISCOVER)
        detector_feed(&det, info->mac);
}

/* ---- SIGINT: clean stop ------------------------------------------------- */

static void on_sigint(int sig)
{
    (void)sig;
    stop_requested = 1;
    dhcp_capture_breakloop(&capture);
}

/* ---- optional DHCP pool polling via NETCONF ----------------------------- */

static int poll_pool_netconf(void)
{
    dhcp_pool_stats_t stats;

    if (netconf_get_pool_stats(&pool_cfg, &stats) != 0)
        return -1;

    detector_pool_update(&det, stats.used, stats.total);
    return 0;
}

static uint32_t rrd_step_secs(void)
{
    return cfg_get_u32("rrd.step_secs",
                       cfg_get_u32("detector.rrd.step_secs", 10u));
}

/* ---- main --------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [--config FILE] <interface> [router_ip] [user] [password]\n"
        "\n"
        "  Standalone real-time test for the detector module.\n"
        "  It captures DHCP packets through dhcp_parser/, feeds only DHCP\n"
        "  DISCOVERs into detector/, writes RRD samples, and optionally polls\n"
        "  DHCP pool state through NETCONF. It does not enable mitigation and\n"
        "  does not run the reputation pipeline.\n"
        "\n"
        "  Features under test:\n"
        "    F1 - intentionally absent; removed because it caused false positives\n"
        "    F2 - Unique MAC pressure\n"
        "    F3 - Leaky bucket absolute rate\n"
        "    F4 - Adaptive EMA/baseline score\n"
        "    F5 - Locally-administered MAC ratio\n"
        "    F6 - DHCP pool pressure, if NETCONF pool polling is enabled\n"
        "\n"
        "  Attack decision follows the configured detector.score_threshold,\n"
        "  or F6=1 for pool-pressure attacks.\n"
        "\n"
        "options:\n"
        "  --config FILE  optional YAML config path; if omitted, the test uses\n"
        "                 DHCP_DEFENSE_CONFIG, config/config.yaml, the project\n"
        "                 default config path, or compiled defaults as fallback\n"
        "\n"
        "arguments:\n"
        "  interface  network interface to monitor, for example ens160 or eth0\n"
        "  router_ip  optional NETCONF router address for DHCP pool polling\n"
        "  user       optional NETCONF SSH user; default: netconf.username/root\n"
        "  password   optional NETCONF SSH password; default: netconf.password\n"
        "\n"
        "examples:\n"
        "  sudo %s ens160\n"
        "  sudo %s --config src/defense/dhcp_starvation_detector/config/config.yaml eth0\n"
        "  sudo %s ens160 192.168.42.4\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    const char *pos[4];
    int pos_count = 0;
    const char *iface;
    time_t next_pool_poll;
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
                fprintf(stderr, "[FAIL] [test_detector] --config requires a value\n");
                usage(argv[0]);
                return 1;
            }
            config_path = argv[i];
            continue;
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "[FAIL] [test_detector] unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        if (pos_count >= 4) {
            fprintf(stderr, "[FAIL] [test_detector] too many positional arguments\n");
            usage(argv[0]);
            return 1;
        }
        pos[pos_count++] = argv[i];
    }

    if (pos_count < 1) {
        fprintf(stderr, "[FAIL] [test_detector] missing interface\n");
        usage(argv[0]);
        return 1;
    }

    setbuf(stdout, NULL);

    if (load_test_config(config_path) != 0)
        return 1;

    iface = pos[0];
    if (detector_init(&det) != 0)
        return 1;

    if (pos_count >= 2) {
        memset(&pool_cfg, 0, sizeof(pool_cfg));
        strncpy(pool_cfg.host, pos[1], sizeof(pool_cfg.host) - 1);
        strncpy(pool_cfg.username,
                pos_count >= 3 ? pos[2] : cfg_get_string("netconf.username", "root"),
                sizeof(pool_cfg.username) - 1);
        strncpy(pool_cfg.password,
                pos_count >= 4 ? pos[3] : cfg_get_string("netconf.password", ""),
                sizeof(pool_cfg.password) - 1);
        pool_cfg.port = (uint16_t)cfg_get_u32("netconf.port",
                                              NETCONF_PORT_DEFAULT);
        pool_netconf_enabled = 1;
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
        fprintf(stderr, "[FAIL] [test_detector] %s\n", errbuf);
        return 1;
    }

    signal(SIGINT, on_sigint);

    printf("[test_detector] interface   : %s\n", iface);
    printf("[test_detector] config      : %s\n", cfg_loaded_path());
    printf("[test_detector] window      : %d seconds\n",
           cfg_get_int("detector.window_secs", 60));
    printf("[test_detector] leaky bucket: capacity=%.0f  refill=%.0f/sec\n",
           det.lb.capacity, det.lb.refill_per_sec);
    printf("[test_detector] unique MACs : threshold=%u in %d seconds\n",
           cfg_get_u32("detector.unique_mac_threshold", 40u),
           cfg_get_int("detector.window_secs", 60));
    printf("[test_detector] Z-score     : alpha=%.2f  delta=%.1f  warmup=%us\n",
           cfg_get_double("detector.adaptive_score.alpha", 0.10),
           cfg_get_double("detector.adaptive_score.delta", 1.50),
           cfg_get_u32("detector.adaptive_score.warmup", 120u));
    printf("[test_detector] LA-bit      : threshold=%.2f over %ds\n",
           cfg_get_float("detector.la_threshold", 0.80f),
           cfg_get_int("detector.la_window_secs", 5));
    printf("[test_detector] pool        : ");
    if (pool_netconf_enabled) {
        printf("NETCONF %s:%u, polled every %us\n",
               pool_cfg.host, pool_cfg.port, detector_pool_poll_secs());
        if (poll_pool_netconf() != 0)
            fprintf(stderr,
                    "[WARN] [test_detector] first NETCONF pool poll failed; continuing\n");
    } else {
        printf("disabled\n");
    }
    printf("[test_detector] score limit : %d/5 or F6=1 to raise the alert\n",
           cfg_get_int("detector.score_threshold", 2));
    printf("[test_detector] rrd         : %s  (updated every %ds)\n\n",
           cfg_resolve_path("paths.rrd_file", "db/dhcp_stats.rrd"),
           (int)rrd_step_secs());

    next_pool_poll = time(NULL) + detector_pool_poll_secs();

    /* Non-blocking mode keeps the main loop alive even without packets,
     * so it can write RRD samples every configured step. */
    while (!stop_requested) {
        time_t now = time(NULL);

        if (pool_netconf_enabled && time(NULL) >= next_pool_poll) {
            if (poll_pool_netconf() != 0)
                fprintf(stderr, "[WARN] [test_detector] NETCONF pool poll failed\n");
            next_pool_poll = time(NULL) + detector_pool_poll_secs();
        }

        if (now != last_tick) {
            detector_tick(&det);
            last_tick = now;
        }

        int rc = dhcp_capture_dispatch(&capture,
                                       cfg_get_int("pcap.dispatch_batch", 64),
                                       on_packet,
                                       NULL,
                                       errbuf,
                                       sizeof(errbuf));

        if (rc == DHCP_CAPTURE_BREAK)
            break;
        if (rc == DHCP_CAPTURE_ERROR) {
            fprintf(stderr, "[FAIL] [test_detector] %s\n", errbuf);
            exit_status = 1;
            break;
        }

        if (detector_rrd_pending(&det))
            detector_rrd_flush(&det);

        usleep((useconds_t)cfg_get_u32("pcap.loop_sleep_us", 100000u));
    }

    dhcp_capture_close(&capture);
    printf("\n[test_detector] stop.\n");
    return exit_status;
}
