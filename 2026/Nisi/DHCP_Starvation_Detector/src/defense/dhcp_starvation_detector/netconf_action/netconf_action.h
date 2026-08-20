#ifndef NETCONF_ACTION_H
#define NETCONF_ACTION_H

#include <stdint.h>
#include "../whitelist/whitelist.h"

#define NETCONF_PORT_DEFAULT 830
#define NETCONF_YANG_NS      "urn:dhcp-starvation-detector"

typedef struct {
    char     host[64];
    uint16_t port;
    char     username[32];
    char     password[64];
} netconf_cfg_t;

typedef struct {
    uint32_t used;
    uint32_t total;
    char     lease_file[128];
} dhcp_pool_stats_t;

/*
 * Push whitelist MACs to the DHCP backend and enable whitelist-only mode.
 * After this call the backend responds only to MACs present in wl.
 * Returns 0 on success, -1 on error.
 */
int netconf_enforce_whitelist(const netconf_cfg_t *cfg, const whitelist_t *wl);

/*
 * Disable whitelist-only mode, restore normal dynamic DHCP.
 * Returns 0 on success, -1 on error.
 */
int netconf_disable_whitelist(const netconf_cfg_t *cfg);

/*
 * Read current DHCP pool usage from the DHCP backend via NETCONF <get>.
 * Returns 0 on success, -1 on error.
 */
int netconf_get_pool_stats(const netconf_cfg_t *cfg, dhcp_pool_stats_t *stats);

/*
 * Find the active lease assigned to a MAC by reading the DHCP lease table
 * via NETCONF <get>. ip is returned in network byte order.
 * Returns 0 if found, 1 if not found, -1 on error.
 */
int netconf_lookup_lease(const netconf_cfg_t *cfg,
                         const uint8_t mac[MAC_LEN],
                         uint32_t *ip);

/*
 * Remove a DHCP lease from the DHCP backend by MAC and/or IP.
 * ip is in network byte order; pass 0 if only the MAC is known.
 * Returns 0 on success, -1 on error.
 */
int netconf_release_lease(const netconf_cfg_t *cfg,
                          const uint8_t mac[MAC_LEN],
                          uint32_t ip);

/*
 * Reset DHCP mitigation state and clear the current DHCP lease pool.
 * The server-specific NETCONF handler decides how this maps to its backend
 * (dnsmasq, ISC DHCP, Kea, etc.).
 * Returns 0 on success, -1 on error.
 */
int netconf_reset_pool(const netconf_cfg_t *cfg);

#endif /* NETCONF_ACTION_H */
