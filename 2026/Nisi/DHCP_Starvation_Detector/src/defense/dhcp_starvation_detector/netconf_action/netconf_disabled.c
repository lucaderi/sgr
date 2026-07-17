#include "netconf_action.h"
#include "netconf_worker.h"

#include <stdio.h>

static int netconf_disabled_error(const char *op)
{
    fprintf(stderr,
            "[FAIL] [defense] NETCONF support is disabled in this build "
            "(operation: %s)\n",
            op);
    return -1;
}

int netconf_enforce_whitelist(const netconf_cfg_t *cfg, const whitelist_t *wl)
{
    (void)cfg;
    (void)wl;
    return netconf_disabled_error("whitelist-on");
}

int netconf_disable_whitelist(const netconf_cfg_t *cfg)
{
    (void)cfg;
    return netconf_disabled_error("whitelist-off");
}

int netconf_get_pool_stats(const netconf_cfg_t *cfg, dhcp_pool_stats_t *stats)
{
    (void)cfg;
    (void)stats;
    return netconf_disabled_error("pool");
}

int netconf_lookup_lease(const netconf_cfg_t *cfg,
                         const uint8_t mac[MAC_LEN],
                         uint32_t *ip)
{
    (void)cfg;
    (void)mac;
    (void)ip;
    return netconf_disabled_error("lease");
}

int netconf_release_lease(const netconf_cfg_t *cfg,
                          const uint8_t mac[MAC_LEN],
                          uint32_t ip)
{
    (void)cfg;
    (void)mac;
    (void)ip;
    return netconf_disabled_error("release-lease");
}

int netconf_reset_pool(const netconf_cfg_t *cfg)
{
    (void)cfg;
    return netconf_disabled_error("reset-pool");
}

int nw_start(const netconf_cfg_t *cfg)
{
    (void)cfg;
    return netconf_disabled_error("worker-start");
}

void nw_stop(void)
{
}

int nw_enqueue(const nw_job_t *job)
{
    (void)job;
    return netconf_disabled_error("worker-enqueue");
}

int nw_dequeue_result(nw_result_t *out)
{
    (void)out;
    return -1;
}
