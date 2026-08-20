#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config/defense_config.h"
#include "detector/detector.h"
#include "dhcp_parser/dhcp_parser.h"
#include "netconf_action/netconf_action.h"
#include "netconf_action/netconf_worker.h"
#include "reputation/mac_reputation.h"
#include "whitelist/whitelist.h"

typedef struct {
    netconf_cfg_t     netconf;
    mac_reputation_t *mr;
    const char       *wl_path;
    int               mitigation_enabled;
    int               whitelist_active;
} defense_ctx_t;

static detector_t det;
static mac_reputation_t mr;
static defense_ctx_t ctx;
static dhcp_capture_t capture;
static volatile sig_atomic_t stop_requested = 0;

static uint32_t lease_lookup_retry_secs(void)
{
    return cfg_get_u32("defense.lease_lookup_retry_secs", 5u);
}

static uint32_t mitigation_grace_secs(void)
{
    return cfg_get_u32("defense.mitigation_grace_secs", 120u);
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

static int reload_whitelist(defense_ctx_t *c)
{
    return whitelist_load(&c->mr->confirmed_wl, c->wl_path);
}

static int push_whitelist(defense_ctx_t *c, const char *reason)
{
    nw_job_t job;

    if (reload_whitelist(c) != 0) {
        fprintf(stderr, "[FAIL] [defense] whitelist reload failed: %s\n", c->wl_path);
        return -1;
    }

    job.type = NW_JOB_ENFORCE_WL;
    job.wl   = c->mr->confirmed_wl;  /* copy */
    if (nw_enqueue(&job) != 0) {
        fprintf(stderr, "[FAIL] [defense] NETCONF whitelist push dropped (%s)\n",
                reason);
        return -1;
    }

    printf("[defense] NETCONF whitelist push queued (%s): %d MACs\n",
           reason, c->mr->confirmed_wl.count);
    return 0;
}

static int queue_disable_whitelist(const char *reason)
{
    nw_job_t job;

    job.type = NW_JOB_DISABLE_WL;
    if (nw_enqueue(&job) != 0) {
        fprintf(stderr, "[FAIL] [defense] NETCONF whitelist disable dropped (%s)\n",
                reason);
        return -1;
    }

    printf("[defense] NETCONF whitelist disable queued (%s)\n", reason);
    return 0;
}

static void on_reputation_promote(const uint8_t mac[6], void *opaque)
{
    defense_ctx_t *c = opaque;
    char mac_str[18];
    int rc;

    mac_to_str(mac, mac_str, sizeof(mac_str));
    rc = whitelist_add(&c->mr->confirmed_wl, mac, "reputation-temporary");

    if (rc < 0) {
        printf("[FAIL] [defense] reputation: failed to add temporary whitelist entry %s\n",
               mac_str);
        return;
    }

    printf("[defense] reputation: temporary whitelist entry %s %s\n",
           mac_str, rc == 1 ? "already present" : "added");

    if (c->whitelist_active &&
        push_whitelist(c, "reputation temporary promotion") != 0) {
        fprintf(stderr,
                "[FAIL] [defense] reputation promotion could not refresh "
                "router whitelist for %s\n",
                mac_str);
    }
}

static void on_reputation_confirm(const uint8_t mac[6], uint32_t ip, void *opaque)
{
    (void)opaque;
    char mac_str[18];
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = ip };

    mac_to_str(mac, mac_str, sizeof(mac_str));
    if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
        snprintf(ip_str, sizeof(ip_str), "unknown");

    printf("[defense] reputation: confirmed %s ip=%s\n", mac_str, ip_str);
}

static void on_reputation_reject(const uint8_t mac[6], uint32_t ip, void *opaque)
{
    defense_ctx_t *c = opaque;
    char mac_str[18];
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = ip };
    int rc;

    mac_to_str(mac, mac_str, sizeof(mac_str));
    if (ip != 0 && !inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
        snprintf(ip_str, sizeof(ip_str), "unknown");
    else if (ip == 0)
        snprintf(ip_str, sizeof(ip_str), "none");

    rc = whitelist_remove(&c->mr->confirmed_wl, mac);
    printf("[defense] reputation: rejected %s ip=%s (%s)\n",
           mac_str, ip_str,
           rc == 0 ? "removed from whitelist" :
           rc == 1 ? "not present in whitelist" :
                     "whitelist update failed");

    if (c->whitelist_active &&
        push_whitelist(c, "reputation rejection") != 0) {
        fprintf(stderr,
                "[FAIL] [defense] reputation rejection could not refresh "
                "router whitelist for %s\n",
                mac_str);
    }

    if (ip != 0) {
        nw_job_t job;
        job.type        = NW_JOB_RELEASE_LEASE;
        memcpy(job.release.mac, mac, MAC_LEN);
        job.release.ip  = ip;
        if (nw_enqueue(&job) != 0) {
            fprintf(stderr,
                    "[FAIL] [defense] NETCONF release-lease dropped for %s\n",
                    mac_str);
        }
    }
}

static void feed_reputation_packet(const dhcp_info_t *info)
{
    uint32_t ip;

    switch (info->msg_type) {
        case DHCP_DISCOVER:
            if (memcmp(info->eth_src, info->mac, MAC_LEN) != 0) {
                char mac_str[18];
                mac_to_str(info->mac, mac_str, sizeof(mac_str));
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
            ip = lease_hint_ip(info);
            if (ip != 0)
                mr_feed_lease_hint(&mr, info->mac, ip,
                                   info->ts.tv_sec, "REQUEST");
            break;

        case DHCP_ACK:
            mr_feed_ack(&mr, info->mac, lease_hint_ip(info), info->ts.tv_sec);
            break;

        default:
            break;
    }
}

static void refresh_reputation_leases(time_t now)
{
    for (int i = 0; i < mr.count; i++) {
        mr_entry_t *e = &mr.table[i];
        nw_job_t job;

        if (e->state != MR_PROVISIONAL)
            continue;
        if (e->arp_next != 0 && now < e->arp_next)
            continue;

        job.type = NW_JOB_LOOKUP_LEASE;
        memcpy(job.mac, e->mac, MAC_LEN);
        if (nw_enqueue(&job) == 0) {
            e->arp_next = now + lease_lookup_retry_secs();
        } else {
            char mac_str[18];
            mac_to_str(e->mac, mac_str, sizeof(mac_str));
            fprintf(stderr,
                    "[WARN] [defense] NETCONF lease lookup dropped for %s; "
                    "will retry\n",
                    mac_str);
            e->arp_next = now + lease_lookup_retry_secs();
        }
    }
}

static void on_packet(const dhcp_info_t *info, void *user)
{
    (void)user;

    if (!info)
        return;

    if (info->msg_type == DHCP_DISCOVER)
        detector_feed(&det, info->mac);

    if (ctx.whitelist_active)
        feed_reputation_packet(info);
}

static void on_sigint(int sig)
{
    (void)sig;
    stop_requested = 1;
    dhcp_capture_breakloop(&capture);
}

static void enable_mitigation(void)
{
    printf("[defense] ATTACK detected: enabling whitelist-only mode\n");
    if (push_whitelist(&ctx, "attack detected") == 0)
        ctx.mitigation_enabled = 1;
    else
        ctx.mitigation_enabled = 0;
}

static int disable_mitigation(void)
{
    printf("[defense] attack ended: disabling whitelist-only mode\n");
    if (queue_disable_whitelist("attack cleared") == 0) {
        ctx.mitigation_enabled = 0;
        return 0;
    }
    return -1;
}

static void poll_pool(void)
{
    nw_job_t job;
    job.type = NW_JOB_POOL_STATS;
    if (nw_enqueue(&job) != 0) {
        fprintf(stderr,
                "[WARN] [defense] NETCONF pool poll dropped; "
                "detection continues on current data\n");
    }
}

static void drain_netconf_results(void)
{
    nw_result_t res;
    time_t now = time(NULL);

    while (nw_dequeue_result(&res) == 0) {
        switch (res.type) {

            case NW_RES_POOL_OK:
                detector_pool_update(&det, res.pool.used, res.pool.total);
                printf("[defense] pool state: %u/%u leases (%.0f%% used, "
                       "growth=%u, tte=%us)\n",
                       det.pool_used,
                       det.pool_total,
                       det.pool_usage * 100.0f,
                       det.pool_growth,
                       det.pool_tte_secs);
                break;

            case NW_RES_POOL_FAIL:
                fprintf(stderr,
                    "[WARN] [defense] NETCONF pool poll failed — F6 has no new data, "
                    "detection continues on F2-F5\n");
                break;

            case NW_RES_ENFORCE_WL_OK:
                if (ctx.mitigation_enabled) {
                    ctx.whitelist_active = 1;
                    printf("[defense] whitelist-only active\n");
                } else {
                    ctx.whitelist_active = 1;
                    printf("[defense] stale whitelist enable completed after attack end; disabling again\n");
                    if (disable_mitigation() != 0)
                        ctx.mitigation_enabled = 1;
                }
                break;

            case NW_RES_LEASE_FOUND: {
                char mac_str[18], ip_str[INET_ADDRSTRLEN];
                struct in_addr a = { .s_addr = res.lease.ip };
                mac_to_str(res.lease.mac, mac_str, sizeof(mac_str));
                if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
                    snprintf(ip_str, sizeof(ip_str), "unknown");
                printf("[defense] NETCONF lease hint: %s -> %s\n",
                       mac_str, ip_str);
                mr_feed_lease_hint(&mr, res.lease.mac, res.lease.ip,
                                   now, "NETCONF-LEASE");
                break;
            }

            case NW_RES_LEASE_NOT_FOUND:
            case NW_RES_LEASE_ERROR:
                /* schedule retry: find the entry and reset arp_next */
                for (int i = 0; i < mr.count; i++) {
                    mr_entry_t *e = &mr.table[i];
                    if (e->state == MR_PROVISIONAL &&
                        memcmp(e->mac, res.mac, MAC_LEN) == 0) {
                        if (res.type == NW_RES_LEASE_ERROR) {
                            char mac_str[18];
                            mac_to_str(res.mac, mac_str, sizeof(mac_str));
                            fprintf(stderr,
                                    "[WARN] [defense] NETCONF lease lookup failed for %s; "
                                    "will retry\n",
                                    mac_str);
                        }
                        e->arp_next = now + lease_lookup_retry_secs();
                        break;
                    }
                }
                break;

            case NW_RES_ENFORCE_WL_FAIL:
                fprintf(stderr,
                    "[FAIL] [defense] NETCONF whitelist enforce failed\n");
                ctx.whitelist_active = 0;
                if (ctx.mitigation_enabled &&
                    push_whitelist(&ctx, "retry after enforce failure") != 0)
                    ctx.mitigation_enabled = 0;
                break;

            case NW_RES_DISABLE_WL_OK:
                ctx.whitelist_active = 0;
                printf("[defense] whitelist-only inactive\n");
                break;

            case NW_RES_DISABLE_WL_FAIL:
                fprintf(stderr,
                    "[FAIL] [defense] NETCONF whitelist disable failed\n");
                if (!ctx.mitigation_enabled &&
                    queue_disable_whitelist("retry after disable failure") != 0)
                    ctx.mitigation_enabled = 1;
                break;

            case NW_RES_RELEASE_LEASE_OK:
                break;

            case NW_RES_RELEASE_LEASE_FAIL: {
                char mac_str[18], ip_str[INET_ADDRSTRLEN];
                struct in_addr a = { .s_addr = res.lease.ip };
                mac_to_str(res.lease.mac, mac_str, sizeof(mac_str));
                if (res.lease.ip != 0 &&
                    !inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
                    snprintf(ip_str, sizeof(ip_str), "unknown");
                else if (res.lease.ip == 0)
                    snprintf(ip_str, sizeof(ip_str), "none");
                fprintf(stderr,
                        "[WARN] [defense] NETCONF lease release failed for %s ip=%s; "
                        "continuing\n",
                        mac_str, ip_str);
                break;
            }

            case NW_RES_RESET_POOL_FAIL:
                fprintf(stderr,
                    "[FAIL] [defense] NETCONF DHCP pool reset failed\n");
                break;
        }
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s [config_file]\n"
            "  %s --router-message MSG [router-message options] [config_file]\n"
            "\n"
            "  Complete DHCP starvation detector program.\n"
            "  It sniffs DHCP traffic, runs the detector, writes RRD stats,\n"
            "  enables/disables whitelist-only mode through NETCONF,\n"
            "  and uses the reputation pipeline to temporarily admit and\n"
            "  validate legitimate hosts during an attack.\n"
            "\n"
            "normal mode:\n"
            "  config_file    optional YAML config path\n"
            "                 default: DHCP_DEFENSE_CONFIG, then config/config.yaml,\n"
            "                 then src/defense/dhcp_starvation_detector/config/config.yaml\n"
            "                 also used by router-message mode to read NETCONF settings\n"
            "\n"
            "router-message mode:\n"
            "  --router-message MSG\n"
            "                 send one NETCONF/YANG command, then exit\n"
            "                 supported MSG values:\n"
            "                   whitelist-on   edit-config whitelist-only=true\n"
            "                   whitelist-off  edit-config whitelist-only=false\n"
            "                   pool           get dhcp-defense/pool stats\n"
            "                   lease          get one lease; requires --router-mac\n"
            "                   release-lease  RPC release-lease; requires --router-mac\n"
            "                   reset-pool     RPC reset-pool\n"
            "                 aliases: on, off, release, reset\n"
            "\n"
            "router-message options:\n"
            "  --router-mac MAC\n"
            "                 required by lease and release-lease\n"
            "  --router-ip IP\n"
            "                 optional IPv4 argument for release-lease\n"
            "  --router-whitelist FILE\n"
            "                 optional whitelist file for whitelist-on\n"
            "                 default: paths.whitelist from config\n"
            "\n"
            "environment overrides:\n"
            "  Any YAML key can be overridden by uppercasing it and replacing '.'\n"
            "  with '_'. Examples: runtime.interface -> RUNTIME_INTERFACE,\n"
            "  netconf.host -> NETCONF_HOST, paths.whitelist -> PATHS_WHITELIST,\n"
            "  dhcp.backend -> DHCP_BACKEND.\n"
            "\n"
            "example:\n"
            "  sudo %s\n"
            "  sudo %s /app/config/config.yaml\n"
            "  sudo %s --router-message reset-pool\n"
            "  sudo %s --router-message pool\n"
            "  sudo %s --router-message lease --router-mac aa:bb:cc:dd:ee:ff\n"
            "  sudo %s --router-message release-lease --router-mac aa:bb:cc:dd:ee:ff --router-ip 192.168.42.123\n"
            "  sudo -E RUNTIME_INTERFACE=ens160 NETCONF_HOST=192.168.42.4 %s\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static int parse_mac_arg(const char *str, uint8_t mac[MAC_LEN])
{
    unsigned int b[MAC_LEN];

    if (!str)
        return -1;

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

static int handle_router_message(const char *msg,
                                 const char *mac_arg,
                                 const char *ip_arg,
                                 const char *wl_arg,
                                 const netconf_cfg_t *cfg,
                                 const char *default_wl_path)
{
    const char *name = router_message_name(msg);

    if (!name) {
        fprintf(stderr, "[FAIL] [defense] --router-message requires a value\n");
        return 1;
    }

    printf("[defense] router-message %s -> %s:%u\n",
           name, cfg->host, cfg->port);

    if (strcmp(name, "whitelist-off") == 0) {
        if (netconf_disable_whitelist(cfg) != 0) {
            fprintf(stderr, "[FAIL] [defense] router-message whitelist-off failed\n");
            return 1;
        }
        printf("[defense] router-message whitelist-off OK\n");
        return 0;
    }

    if (strcmp(name, "pool") == 0) {
        dhcp_pool_stats_t stats;

        if (netconf_get_pool_stats(cfg, &stats) != 0) {
            fprintf(stderr, "[FAIL] [defense] router-message pool failed\n");
            return 1;
        }

        printf("[defense] pool: used=%u total=%u\n",
               stats.used, stats.total);
        if (stats.lease_file[0])
            printf("[defense] lease-file: %s\n", stats.lease_file);
        return 0;
    }

    if (strcmp(name, "reset-pool") == 0) {
        if (netconf_reset_pool(cfg) != 0) {
            fprintf(stderr, "[FAIL] [defense] router-message reset-pool failed\n");
            return 1;
        }
        printf("[defense] router-message reset-pool OK\n");
        return 0;
    }

    if (strcmp(name, "whitelist-on") == 0) {
        whitelist_t wl;
        const char *path = wl_arg && *wl_arg ? wl_arg : default_wl_path;

        if (!path || !*path) {
            fprintf(stderr,
                    "[FAIL] [defense] router-message whitelist-on needs "
                    "--router-whitelist or paths.whitelist\n");
            return 1;
        }

        if (whitelist_load(&wl, path) != 0) {
            fprintf(stderr,
                    "[FAIL] [defense] unable to load whitelist file: %s\n",
                    path);
            return 1;
        }

        printf("[defense] whitelist: %d MACs loaded from %s\n",
               wl.count, path);
        if (netconf_enforce_whitelist(cfg, &wl) != 0) {
            fprintf(stderr, "[FAIL] [defense] router-message whitelist-on failed\n");
            return 1;
        }
        printf("[defense] router-message whitelist-on OK\n");
        return 0;
    }

    if (strcmp(name, "lease") == 0) {
        uint8_t mac[MAC_LEN];
        uint32_t ip = 0;
        int rc;

        if (parse_mac_arg(mac_arg, mac) != 0) {
            fprintf(stderr,
                    "[FAIL] [defense] router-message lease requires a valid "
                    "--router-mac\n");
            return 1;
        }

        rc = netconf_lookup_lease(cfg, mac, &ip);
        if (rc < 0) {
            fprintf(stderr, "[FAIL] [defense] router-message lease failed\n");
            return 1;
        }
        if (rc > 0) {
            printf("[defense] lease: not found\n");
            return 2;
        }

        char ip_str[INET_ADDRSTRLEN];
        struct in_addr a;
        a.s_addr = ip;
        if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
            snprintf(ip_str, sizeof(ip_str), "unknown");
        printf("[defense] lease: %s -> %s\n", mac_arg, ip_str);
        return 0;
    }

    if (strcmp(name, "release-lease") == 0) {
        uint8_t mac[MAC_LEN];
        uint32_t ip = 0;

        if (parse_mac_arg(mac_arg, mac) != 0) {
            fprintf(stderr,
                    "[FAIL] [defense] router-message release-lease requires "
                    "a valid --router-mac\n");
            return 1;
        }
        if (ip_arg && *ip_arg && inet_pton(AF_INET, ip_arg, &ip) != 1) {
            fprintf(stderr,
                    "[FAIL] [defense] router-message release-lease got invalid "
                    "--router-ip: %s\n",
                    ip_arg);
            return 1;
        }

        if (netconf_release_lease(cfg, mac, ip) != 0) {
            fprintf(stderr, "[FAIL] [defense] router-message release-lease failed\n");
            return 1;
        }
        printf("[defense] router-message release-lease OK\n");
        return 0;
    }

    fprintf(stderr,
            "[FAIL] [defense] unsupported router message: %s "
            "(expected whitelist-on, whitelist-off, pool, lease, "
            "release-lease or reset-pool)\n",
            msg);
    return 1;
}

int main(int argc, char *argv[])
{
    const char *iface;
    const char *config_path = NULL;
    const char *dhcp_backend;
    const char *router_message = NULL;
    const char *router_mac = NULL;
    const char *router_ip_arg = NULL;
    const char *router_whitelist = NULL;
    const char *router_ip;
    const char *wl_path;
    const char *user;
    const char *pass;
    time_t last_tick = 0;
    time_t next_pool_poll = 0;
    time_t mitigation_until = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--router-message") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[FAIL] [defense] --router-message requires a value\n");
                usage(argv[0]);
                return 1;
            }
            router_message = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--router-mac") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[FAIL] [defense] --router-mac requires a value\n");
                usage(argv[0]);
                return 1;
            }
            router_mac = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--router-ip") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[FAIL] [defense] --router-ip requires a value\n");
                usage(argv[0]);
                return 1;
            }
            router_ip_arg = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--router-whitelist") == 0) {
            if (++i >= argc) {
                fprintf(stderr,
                        "[FAIL] [defense] --router-whitelist requires a value\n");
                usage(argv[0]);
                return 1;
            }
            router_whitelist = argv[i];
            continue;
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "[FAIL] [defense] unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        if (config_path) {
            fprintf(stderr, "[FAIL] [defense] too many config paths\n");
            usage(argv[0]);
            return 1;
        }
        config_path = argv[i];
    }

    setbuf(stdout, NULL);

    if (config_path) {
        if (cfg_load(config_path) != 0)
            return 1;
    } else if (cfg_load_default() != 0) {
        return 1;
    }

    iface = cfg_get_string("runtime.interface", "");
    dhcp_backend = cfg_get_string("dhcp.backend", "dnsmasq");
    router_ip = cfg_get_string("netconf.host", "");
    wl_path = whitelist_cfg_path();
    user = cfg_get_string("netconf.username", "root");
    pass = cfg_get_string("netconf.password", "");

    if (!router_ip || !*router_ip) {
        fprintf(stderr, "[FAIL] [defense] missing config value: netconf.host\n");
        return 1;
    }
    if (strcmp(dhcp_backend, "dnsmasq") != 0 &&
        strcmp(dhcp_backend, "isc") != 0) {
        fprintf(stderr,
                "[FAIL] [defense] invalid config value: dhcp.backend=%s "
                "(expected dnsmasq or isc)\n",
                dhcp_backend);
        return 1;
    }

    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.netconf.host, router_ip, sizeof(ctx.netconf.host) - 1);
    strncpy(ctx.netconf.username, user, sizeof(ctx.netconf.username) - 1);
    strncpy(ctx.netconf.password, pass, sizeof(ctx.netconf.password) - 1);
    ctx.netconf.port = (uint16_t)cfg_get_u32("netconf.port",
                                             NETCONF_PORT_DEFAULT);
    ctx.mr = &mr;
    ctx.wl_path = wl_path;

    if (router_message) {
        return handle_router_message(router_message,
                                     router_mac,
                                     router_ip_arg,
                                     router_whitelist,
                                     &ctx.netconf,
                                     wl_path);
    }

    if (!iface || !*iface) {
        fprintf(stderr, "[FAIL] [defense] missing config value: runtime.interface\n");
        return 1;
    }

    if (detector_init(&det) != 0)
        return 1;

    if (nw_start(&ctx.netconf) != 0) {
        fprintf(stderr, "[FAIL] [defense] failed to start NETCONF worker thread\n");
        return 1;
    }

    mr_init(&mr, iface,
            on_reputation_promote,
            on_reputation_confirm,
            on_reputation_reject,
            &ctx);
    if (mr_enable_confirmed_whitelist(&mr, wl_path) != 0) {
        fprintf(stderr, "[FAIL] [defense] unable to load whitelist DB: %s\n", wl_path);
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
        fprintf(stderr, "[FAIL] [defense] %s\n", errbuf);
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    printf("[defense] interface : %s\n", iface);
    printf("[defense] config    : %s\n", cfg_loaded_path());
    printf("[defense] dhcp      : %s\n", dhcp_backend);
    printf("[defense] router    : %s:%u\n", ctx.netconf.host, ctx.netconf.port);
    printf("[defense] whitelist : %s\n", wl_path);
    printf("[defense] user      : %s\n\n", ctx.netconf.username);

    poll_pool();
    {
        time_t pool_boot_deadline = time(NULL) + 3;
        while (!stop_requested &&
               det.pool_total == 0 &&
               time(NULL) < pool_boot_deadline) {
            drain_netconf_results();
            if (det.pool_total != 0)
                break;
            usleep(100000);
        }
    }
    next_pool_poll = time(NULL) + detector_pool_poll_secs();

    while (!stop_requested) {
        time_t now = time(NULL);

        if (now >= next_pool_poll) {
            poll_pool();
            next_pool_poll = now + detector_pool_poll_secs();
        }

        if (now != last_tick) {
            int attack_now;

            detector_tick(&det);
            if (ctx.whitelist_active)
                refresh_reputation_leases(now);
            mr_tick(&mr, now);

            attack_now = detector_attack_active(&det);
            if (attack_now) {
                mitigation_until = now + mitigation_grace_secs();

                if (!ctx.mitigation_enabled)
                    enable_mitigation();
            } else if (ctx.mitigation_enabled &&
                       mitigation_until != 0 &&
                       now >= mitigation_until) {
                disable_mitigation();
            }
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
            fprintf(stderr, "[FAIL] [defense] %s\n", errbuf);
            break;
        }

        drain_netconf_results();

        if (detector_rrd_pending(&det))
            detector_rrd_flush(&det);

        usleep((useconds_t)cfg_get_u32("pcap.loop_sleep_us", 100000u));
    }

    if (ctx.mitigation_enabled)
        disable_mitigation();

    nw_stop();

    dhcp_capture_close(&capture);
    printf("\n[defense] stop.\n");
    return 0;
}
