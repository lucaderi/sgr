#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "netconf_action.h"
#include "../config/defense_config.h"
#include "../whitelist/whitelist.h"

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
            "[WARN] [test_netconf] config file not found; using compiled "
            "defaults and environment overrides.\n");
    cfg_use_defaults(".");
    return 0;
}

static int parse_mac_arg(const char *str, uint8_t mac[MAC_LEN])
{
    unsigned int b[MAC_LEN];

    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != MAC_LEN)
        return -1;

    for (int i = 0; i < MAC_LEN; i++) {
        if (b[i] > 0xff)
            return -1;
        mac[i] = (uint8_t)b[i];
    }

    return 0;
}

static const char *router_message_name(const char *msg)
{
    if (!msg)
        return NULL;
    if (strcmp(msg, "on") == 0)
        return "whitelist-on";
    if (strcmp(msg, "off") == 0)
        return "whitelist-off";
    if (strcmp(msg, "release") == 0)
        return "release-lease";
    if (strcmp(msg, "reset") == 0)
        return "reset-pool";
    return msg;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [--config FILE] MSG <router_ip> [message arguments]\n"
        "\n"
        "  Standalone test utility for the NETCONF action layer.\n"
        "  It sends one router message to the NETCONF/YANG handler and exits.\n"
        "  This exercises netconf_action/ directly, without packet capture,\n"
        "  detector scoring, reputation, or the async NETCONF worker thread.\n"
        "\n"
        "options:\n"
        "  --config FILE  optional YAML config path; if omitted, the test uses\n"
        "                 DHCP_DEFENSE_CONFIG, config/config.yaml, the project\n"
        "                 default config path, or compiled defaults as fallback\n"
        "\n"
        "MSG values:\n"
        "  whitelist-on   <router_ip> <whitelist_file> [user] [password]\n"
        "                 push whitelist MACs and enable whitelist-only mode\n"
        "  whitelist-off  <router_ip> [user] [password]\n"
        "                 disable whitelist-only mode and restore dynamic DHCP\n"
        "  pool           <router_ip> [user] [password]\n"
        "                 read DHCP pool usage via NETCONF\n"
        "  lease          <router_ip> <mac> [user] [password]\n"
        "                 read one DHCP lease by MAC via NETCONF\n"
        "  release-lease  <router_ip> <mac> [ip] [user] [password]\n"
        "                 remove one DHCP lease by MAC and optional IPv4 address\n"
        "  reset-pool     <router_ip> [user] [password]\n"
        "                 disable whitelist-only mode and clear the DHCP lease pool\n"
        "\n"
        "aliases:\n"
        "  on=whitelist-on, off=whitelist-off, release=release-lease,\n"
        "  reset=reset-pool\n"
        "\n"
        "  router_ip      - NETCONF endpoint IP address\n"
        "  whitelist_file - file with one MAC per line (for example db/whitelist.txt)\n"
        "  user           - SSH user on the router; default: netconf.username/root\n"
        "  password       - SSH password on the router; default: netconf.password\n"
        "  port           - read from netconf.port in config; default: 830\n"
        "\n"
        "examples:\n"
        "  %s whitelist-on  192.168.1.1 db/whitelist.txt\n"
        "  %s whitelist-off 192.168.1.1\n"
        "  %s pool 192.168.1.1\n"
        "  %s lease 192.168.1.1 aa:bb:cc:dd:ee:ff\n"
        "  %s release-lease 192.168.1.1 aa:bb:cc:dd:ee:ff 192.168.1.42\n"
        "  %s reset-pool 192.168.1.1\n"
        "  %s --config src/defense/dhcp_starvation_detector/config/config.yaml pool 192.168.42.4\n",
        prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *config_path = NULL;
    int argi = 1;

    while (argi < argc) {
        if (strcmp(argv[argi], "-h") == 0 ||
            strcmp(argv[argi], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[argi], "--config") == 0) {
            if (++argi >= argc) {
                fprintf(stderr, "[FAIL] [test_netconf] --config requires a value\n");
                usage(argv[0]);
                return 1;
            }
            config_path = argv[argi++];
            continue;
        }
        break;
    }

    if (load_test_config(config_path) != 0)
        return 1;

    if (argc - argi < 2) {
        fprintf(stderr, "[FAIL] [test_netconf] missing MSG or router_ip\n");
        usage(argv[0]);
        return 1;
    }

    const char *cmd_arg   = argv[argi++];
    const char *cmd       = router_message_name(cmd_arg);
    const char *router_ip = argv[argi++];

    int is_on  = (strcmp(cmd, "whitelist-on")  == 0);
    int is_off = (strcmp(cmd, "whitelist-off") == 0);
    int is_pool = (strcmp(cmd, "pool") == 0);
    int is_lease = (strcmp(cmd, "lease") == 0);
    int is_release = (strcmp(cmd, "release-lease") == 0);
    int is_reset = (strcmp(cmd, "reset-pool") == 0);

    if (!is_on && !is_off && !is_pool && !is_lease && !is_release &&
        !is_reset) {
        fprintf(stderr,
                "[FAIL] [test_netconf] invalid MSG '%s'\n\n",
                cmd_arg);
        usage(argv[0]);
        return 1;
    }

    const char *wl_path = NULL;
    const char *mac_arg = NULL;
    const char *user    = cfg_get_string("netconf.username", "root");
    const char *pass    = cfg_get_string("netconf.password", "");
    uint32_t release_ip = 0;

    if (is_on) {
        if (argi >= argc) {
            fprintf(stderr,
                    "[FAIL] [test_netconf] whitelist-on requires whitelist_file\n\n");
            usage(argv[0]);
            return 1;
        }
        wl_path = argv[argi++];
    }

    if (is_lease || is_release) {
        if (argi >= argc) {
            fprintf(stderr,
                    "[FAIL] [test_netconf] %s requires a MAC address\n\n",
                    cmd);
            usage(argv[0]);
            return 1;
        }
        mac_arg = argv[argi++];
    }

    if (is_release && argi < argc) {
        uint32_t ip_tmp;
        if (inet_pton(AF_INET, argv[argi], &ip_tmp) == 1) {
            release_ip = ip_tmp;
            argi++;
        }
    }

    if (argi < argc)
        user = argv[argi++];
    if (argi < argc)
        pass = argv[argi++];
    if (argi < argc) {
        fprintf(stderr, "[FAIL] [test_netconf] too many message arguments\n\n");
        usage(argv[0]);
        return 1;
    }

    netconf_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.host,     router_ip, sizeof(cfg.host)     - 1);
    strncpy(cfg.username, user,      sizeof(cfg.username) - 1);
    strncpy(cfg.password, pass,      sizeof(cfg.password) - 1);
    cfg.port = (uint16_t)cfg_get_u32("netconf.port",
                                     NETCONF_PORT_DEFAULT);

    printf("[test_netconf] router   : %s:%u\n", cfg.host, cfg.port);
    printf("[test_netconf] user     : %s\n",    cfg.username);
    printf("[test_netconf] config   : %s\n",    cfg_loaded_path());
    printf("[test_netconf] command  : %s\n\n",  cmd);

    if (is_off) {
        return netconf_disable_whitelist(&cfg) == 0 ? 0 : 1;
    }

    if (is_pool) {
        dhcp_pool_stats_t stats;

        if (netconf_get_pool_stats(&cfg, &stats) != 0)
            return 1;

        printf("[test_netconf] pool     : %u/%u leases\n",
               stats.used, stats.total);
        if (stats.lease_file[0])
            printf("[test_netconf] leasefile: %s\n", stats.lease_file);

        return 0;
    }

    if (is_reset) {
        return netconf_reset_pool(&cfg) == 0 ? 0 : 1;
    }

    if (is_lease) {
        uint8_t mac[MAC_LEN];
        uint32_t ip = 0;
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr a;
        int rc;

        if (parse_mac_arg(mac_arg, mac) != 0) {
            fprintf(stderr, "[FAIL] [test_netconf] invalid MAC address '%s'\n",
                    mac_arg);
            return 1;
        }

        rc = netconf_lookup_lease(&cfg, mac, &ip);
        if (rc < 0)
            return 1;
        if (rc > 0) {
            printf("[test_netconf] lease    : not found\n");
            return 2;
        }

        a.s_addr = ip;
        if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str))) {
            fprintf(stderr,
                    "[FAIL] [test_netconf] failed to format lease IP address\n");
            return 1;
        }
        printf("[test_netconf] lease    : %s -> %s\n", mac_arg, ip_str);
        return 0;
    }

    if (is_release) {
        uint8_t mac[MAC_LEN];

        if (parse_mac_arg(mac_arg, mac) != 0) {
            fprintf(stderr, "[FAIL] [test_netconf] invalid MAC address '%s'\n",
                    mac_arg);
            return 1;
        }

        if (netconf_release_lease(&cfg, mac, release_ip) != 0)
            return 1;

        printf("[test_netconf] lease release OK\n");
        return 0;
    }

    /* is_on: load the whitelist and send it. */
    whitelist_t wl;
    if (whitelist_load(&wl, wl_path) != 0) {
        fprintf(stderr,
                "[FAIL] [test_netconf] unable to load whitelist from '%s'\n",
                wl_path);
        return 1;
    }
    printf("[test_netconf] whitelist: %d MACs loaded from %s\n\n", wl.count, wl_path);

    return netconf_enforce_whitelist(&cfg, &wl) == 0 ? 0 : 1;
}
