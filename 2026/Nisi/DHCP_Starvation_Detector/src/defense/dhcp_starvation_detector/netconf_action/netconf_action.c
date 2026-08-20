#include "netconf_action.h"

#include <nc_client.h>
#include <libyang/libyang.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../config/defense_config.h"

static int netconf_send_timeout_ms(void)
{
    return cfg_get_int("netconf.send_timeout_ms", 1000);
}

static int netconf_reply_timeout_ms(void)
{
    return cfg_get_int("netconf.reply_timeout_ms", 15000);
}

/* ---- XML builder -------------------------------------------------------- */

/*
 * Builds the <dhcp-defense> XML payload for edit-config.
 * If enable=1, sets whitelist-only=true and appends one <trusted-host>
 * for each MAC in wl. If enable=0, sets whitelist-only=false (wl ignored).
 * Caller must free() the returned string.
 */
static char *build_xml(int enable, const whitelist_t *wl)
{
    int mac_count = (enable && wl) ? wl->count : 0;

    /* ~70 bytes per MAC entry, ~128 for wrapper tags */
    int size = 128 + mac_count * 72;
    char *buf = malloc(size);
    if (!buf) return NULL;

    int n = 0;
    int wrote = snprintf(buf + n, size - n,
                         "<dhcp-defense xmlns=\"" NETCONF_YANG_NS "\">"
                         "<whitelist-only>%s</whitelist-only>",
                         enable ? "true" : "false");
    if (wrote < 0 || wrote >= size - n)
        goto overflow;
    n += wrote;

    for (int i = 0; i < mac_count; i++) {
        const uint8_t *m = wl->macs[i];
        wrote = snprintf(buf + n, size - n,
                         "<trusted-host><mac>"
                         "%02x:%02x:%02x:%02x:%02x:%02x"
                         "</mac></trusted-host>",
                         m[0], m[1], m[2], m[3], m[4], m[5]);
        if (wrote < 0 || wrote >= size - n)
            goto overflow;
        n += wrote;
    }

    wrote = snprintf(buf + n, size - n, "</dhcp-defense>");
    if (wrote < 0 || wrote >= size - n)
        goto overflow;
    return buf;

overflow:
    fprintf(stderr, "[FAIL] [netconf_action] whitelist XML buffer too small\n");
    free(buf);
    return NULL;
}

/* ---- NETCONF helpers ---------------------------------------------------- */

static const char *g_password = NULL;

static char *password_clb(const char *username, const char *hostname, void *priv)
{
    (void)username; (void)hostname; (void)priv;
    return strdup(g_password ? g_password : "");
}

#ifdef HAVE_NC_AUTH_HOSTKEY_CHECK_CLB
static int accept_hostkey_clb(const char *hostname, ssh_session session,
                              void *priv)
{
    (void)hostname;
    (void)session;
    (void)priv;
    return 0;
}
#endif

static struct nc_session *session_open(const netconf_cfg_t *cfg)
{
    if (!cfg) {
        fprintf(stderr, "[FAIL] [netconf_action] missing NETCONF config\n");
        return NULL;
    }

    if (cfg_load_default() != 0) {
        fprintf(stderr,
                "[WARN] [netconf_action] config not loaded; continuing with "
                "compiled defaults and environment overrides\n");
    }

    nc_client_init();

    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(cfg_get_string("netconf.yang_dir",
                                  "/usr/share/yang/modules/libnetconf2"),
                   0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to create libyang context\n");
        return NULL;
    }
    if (ly_ctx_set_searchdir(ctx, ".") != LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] could not add current directory to YANG search path\n");
    if (ly_ctx_set_searchdir(ctx, "netconf_action") != LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] could not add netconf_action to YANG search path\n");

    /*
     * The endpoint is a tiny custom NETCONF handler, not a full server with
     * :validate support. Loading only writable-running keeps the generated
     * RPC aligned with the capabilities advertised by the handler.
     */
    const char *features[] = {"writable-running", NULL};
    if (!ly_ctx_load_module(ctx, "ietf-netconf", NULL, features)) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to load ietf-netconf module\n");
        ly_ctx_destroy(ctx);
        return NULL;
    }
    if (!ly_ctx_load_module(ctx, "dhcp-whitelist", NULL, NULL))
        fprintf(stderr,
                "[WARN] [netconf_action] optional dhcp-whitelist YANG module "
                "not loaded locally\n");

    nc_client_ssh_set_username(cfg->username);
    g_password = cfg->password;
    nc_client_ssh_set_auth_password_clb(password_clb, NULL);
#ifdef HAVE_NC_KNOWNHOSTS_MODE
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_ACCEPT_NEW);
#elif defined(HAVE_NC_AUTH_HOSTKEY_CHECK_CLB)
    nc_client_ssh_set_auth_hostkey_check_clb(accept_hostkey_clb, NULL);
#else
#error "No supported libnetconf2 SSH known-hosts API was detected."
#endif

    struct nc_session *s = nc_connect_ssh(cfg->host, cfg->port, ctx);
    if (!s) {
        fprintf(stderr, "[FAIL] [netconf_action] cannot connect to %s:%u\n",
                cfg->host, cfg->port);
        ly_ctx_destroy(ctx);
    }
    return s;
}

static void session_close(struct nc_session *s)
{
    if (s)
        nc_session_free(s, NULL);
    nc_client_destroy();
}

/*
 * Successful edit-config reply: <rpc-reply><ok/></rpc-reply>.
 * Print the envelope to a string and look for the <ok tag.
 */
static int reply_is_ok(const struct lyd_node *envp)
{
    if (!envp) return 0;
    char *xml = NULL;
    if (lyd_print_mem(&xml, envp, LYD_XML, LYD_PRINT_WITHSIBLINGS) !=
        LY_SUCCESS)
        return 0;
    int ok = xml && strstr(xml, "<ok") != NULL;
    free(xml);
    return ok;
}

static const char *xml_open_content(const char *xml, const char *tag)
{
    size_t tag_len = strlen(tag);
    const char *p = xml;

    while ((p = strchr(p, '<')) != NULL) {
        const char *name;
        const char *name_end;
        const char *local;
        const char *end;

        p++;
        if (*p == '/' || *p == '?' || *p == '!')
            continue;

        name = p;
        while (*p && *p != '>' && *p != '/' && *p != ' ' &&
               *p != '\t' && *p != '\r' && *p != '\n') {
            p++;
        }
        name_end = p;

        local = name;
        for (const char *q = name; q < name_end; q++) {
            if (*q == ':')
                local = q + 1;
        }

        if ((size_t)(name_end - local) != tag_len ||
            strncmp(local, tag, tag_len) != 0) {
            continue;
        }

        end = strchr(p, '>');
        if (!end || (end > xml && *(end - 1) == '/'))
            return NULL;

        return end + 1;
    }

    return NULL;
}

static const char *xml_close_tag(const char *xml, const char *tag)
{
    size_t tag_len = strlen(tag);
    const char *p = xml;

    while ((p = strstr(p, "</")) != NULL) {
        const char *name = p + 2;
        const char *name_end = name;
        const char *local = name;

        while (*name_end && *name_end != '>')
            name_end++;

        for (const char *q = name; q < name_end; q++) {
            if (*q == ':')
                local = q + 1;
        }

        if ((size_t)(name_end - local) == tag_len &&
            strncmp(local, tag, tag_len) == 0) {
            return p;
        }

        p += 2;
    }

    return NULL;
}

static int xml_get_text(const char *xml, const char *tag,
                        char *out, size_t out_size)
{
    const char *start = xml_open_content(xml, tag);
    const char *end;
    size_t len;

    if (!start || out_size == 0)
        return -1;

    end = xml_close_tag(start, tag);
    if (!end || end < start)
        return -1;

    len = (size_t)(end - start);
    if (len >= out_size)
        len = out_size - 1;

    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int xml_get_u32(const char *xml, const char *tag, uint32_t *out)
{
    char buf[32];
    char *end = NULL;
    unsigned long v;

    if (xml_get_text(xml, tag, buf, sizeof(buf)) != 0)
        return -1;

    errno = 0;
    v = strtoul(buf, &end, 10);
    if (errno || end == buf || v > UINT32_MAX)
        return -1;

    *out = (uint32_t)v;
    return 0;
}

static void mac_to_text(const uint8_t mac[MAC_LEN],
                        char *out, size_t out_size)
{
    snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int send_edit_config(struct nc_session *session, const char *xml_config)
{
    uint64_t msgid;
    struct lyd_node *envp = NULL, *op = NULL;
    int rc = -1;

    struct nc_rpc *rpc = nc_rpc_edit(NC_DATASTORE_RUNNING,
                                     NC_RPC_EDIT_DFLTOP_MERGE,
                                     NC_RPC_EDIT_TESTOPT_UNKNOWN,
                                     NC_RPC_EDIT_ERROPT_STOP,
                                     xml_config,
                                     NC_PARAMTYPE_CONST);
    if (!rpc) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to create edit-config RPC\n");
        return -1;
    }

    if (nc_send_rpc(session, rpc, netconf_send_timeout_ms(), &msgid) !=
        NC_MSG_RPC) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to send RPC\n");
        goto out;
    }

    if (nc_recv_reply(session, rpc, msgid, netconf_reply_timeout_ms(),
                      &envp, &op) != NC_MSG_REPLY) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to receive reply\n");
        goto out;
    }

    if (!reply_is_ok(envp)) {
        fprintf(stderr, "[FAIL] [netconf_action] server replied with error\n");
        goto out;
    }

    rc = 0;
    printf("netconf_action: edit-config OK\n");

out:
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    return rc;
}

static int send_get_pool_stats(struct nc_session *session,
                               dhcp_pool_stats_t *stats)
{
    uint64_t msgid;
    struct lyd_node *envp = NULL, *op = NULL;
    char *env_xml = NULL;
    char *op_xml = NULL;
    const char *xml = NULL;
    int rc = -1;

    struct nc_rpc *rpc = nc_rpc_get(NULL, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    if (!rpc) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to create get RPC\n");
        return -1;
    }

    if (nc_send_rpc(session, rpc, netconf_send_timeout_ms(), &msgid) !=
        NC_MSG_RPC) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to send get RPC\n");
        goto out;
    }

    if (nc_recv_reply(session, rpc, msgid, netconf_reply_timeout_ms(),
                      &envp, &op) != NC_MSG_REPLY) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to receive get reply\n");
        goto out;
    }

    if (envp && lyd_print_mem(&env_xml, envp, LYD_XML, LYD_PRINT_WITHSIBLINGS) !=
        LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] failed to print get envelope\n");
    if (op && lyd_print_mem(&op_xml, op, LYD_XML, LYD_PRINT_WITHSIBLINGS) !=
        LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] failed to print get payload\n");

    if (op_xml && strstr(op_xml, "<used"))
        xml = op_xml;
    else if (env_xml)
        xml = env_xml;

    if (!xml) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to print get reply\n");
        goto out;
    }

    memset(stats, 0, sizeof(*stats));
    if (xml_get_u32(xml, "used", &stats->used) != 0 ||
        xml_get_u32(xml, "total", &stats->total) != 0 ||
        stats->total == 0) {
        fprintf(stderr, "[FAIL] [netconf_action] pool stats not found in NETCONF reply\n");
        if (env_xml)
            fprintf(stderr, "[WARN] [netconf_action] reply envelope: %s\n", env_xml);
        if (op_xml)
            fprintf(stderr, "[WARN] [netconf_action] reply payload: %s\n", op_xml);
        goto out;
    }
    (void)xml_get_text(xml, "lease-file", stats->lease_file,
                       sizeof(stats->lease_file));

    rc = 0;

out:
    free(env_xml);
    free(op_xml);
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    return rc;
}

static int send_lookup_lease(struct nc_session *session,
                             const uint8_t mac[MAC_LEN],
                             uint32_t *ip)
{
    uint64_t msgid;
    struct lyd_node *envp = NULL, *op = NULL;
    char *env_xml = NULL;
    char *op_xml = NULL;
    const char *xml = NULL;
    char wanted_mac[18];
    int rc = -1;

    struct nc_rpc *rpc = nc_rpc_get(NULL, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    if (!rpc) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to create lease lookup RPC\n");
        return -1;
    }

    if (nc_send_rpc(session, rpc, netconf_send_timeout_ms(), &msgid) !=
        NC_MSG_RPC) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to send lease lookup RPC\n");
        goto out;
    }

    if (nc_recv_reply(session, rpc, msgid, netconf_reply_timeout_ms(),
                      &envp, &op) != NC_MSG_REPLY) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to receive lease lookup reply\n");
        goto out;
    }

    if (envp && lyd_print_mem(&env_xml, envp, LYD_XML, LYD_PRINT_WITHSIBLINGS) !=
        LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] failed to print lease lookup envelope\n");
    if (op && lyd_print_mem(&op_xml, op, LYD_XML, LYD_PRINT_WITHSIBLINGS) !=
        LY_SUCCESS)
        fprintf(stderr, "[WARN] [netconf_action] failed to print lease lookup payload\n");

    if (op_xml && strstr(op_xml, "<lease"))
        xml = op_xml;
    else if (env_xml)
        xml = env_xml;

    if (!xml) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to print lease lookup reply\n");
        goto out;
    }

    mac_to_text(mac, wanted_mac, sizeof(wanted_mac));

    const char *scan = xml;
    while (1) {
        const char *lease_start = xml_open_content(scan, "lease");
        const char *lease_end;
        char block[256];
        char lease_mac[32];
        char lease_ip[64];
        size_t len;

        if (!lease_start)
            break;

        lease_end = xml_close_tag(lease_start, "lease");
        if (!lease_end || lease_end <= lease_start)
            break;

        len = (size_t)(lease_end - lease_start);
        if (len >= sizeof(block))
            len = sizeof(block) - 1;
        memcpy(block, lease_start, len);
        block[len] = '\0';

        if (xml_get_text(block, "mac", lease_mac, sizeof(lease_mac)) == 0 &&
            xml_get_text(block, "ip", lease_ip, sizeof(lease_ip)) == 0 &&
            strcmp(lease_mac, wanted_mac) == 0) {
            struct in_addr a;

            if (inet_pton(AF_INET, lease_ip, &a) != 1) {
                fprintf(stderr, "[FAIL] [netconf_action] invalid lease IP '%s'\n",
                        lease_ip);
                goto out;
            }

            if (ip)
                *ip = a.s_addr;
            rc = 0;
            goto out;
        }

        scan = lease_end + strlen("</lease>");
    }

    rc = 1;

out:
    free(env_xml);
    free(op_xml);
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    return rc;
}

static int send_generic_ok_rpc(struct nc_session *session,
                               const char *xml,
                               const char *op_name)
{
    uint64_t msgid;
    struct lyd_node *envp = NULL, *op = NULL;
    int rc = -1;

    struct nc_rpc *rpc = nc_rpc_act_generic_xml(xml, NC_PARAMTYPE_CONST);
    if (!rpc) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to create %s RPC\n", op_name);
        return -1;
    }

    if (nc_send_rpc(session, rpc, netconf_send_timeout_ms(), &msgid) !=
        NC_MSG_RPC) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to send %s RPC\n", op_name);
        goto out;
    }

    if (nc_recv_reply(session, rpc, msgid, netconf_reply_timeout_ms(),
                      &envp, &op) != NC_MSG_REPLY) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to receive %s reply\n", op_name);
        goto out;
    }

    if (!reply_is_ok(envp)) {
        fprintf(stderr, "[FAIL] [netconf_action] server rejected %s RPC\n", op_name);
        goto out;
    }

    rc = 0;

out:
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    return rc;
}

/* ---- Public API --------------------------------------------------------- */

int netconf_enforce_whitelist(const netconf_cfg_t *cfg, const whitelist_t *wl)
{
    struct nc_session *s = session_open(cfg);
    if (!s) return -1;

    char *xml = build_xml(1, wl);
    if (!xml) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to build whitelist XML\n");
        session_close(s);
        return -1;
    }

    printf("netconf_action: enforcing whitelist-only mode (%d MAC%s)\n",
           wl ? wl->count : 0, wl && wl->count != 1 ? "s" : "");

    int rc = send_edit_config(s, xml);

    free(xml);
    session_close(s);
    return rc;
}

int netconf_disable_whitelist(const netconf_cfg_t *cfg)
{
    struct nc_session *s = session_open(cfg);
    if (!s) return -1;

    char *xml = build_xml(0, NULL);
    if (!xml) {
        fprintf(stderr, "[FAIL] [netconf_action] failed to build whitelist disable XML\n");
        session_close(s);
        return -1;
    }

    printf("netconf_action: disabling whitelist-only mode\n");

    int rc = send_edit_config(s, xml);

    free(xml);
    session_close(s);
    return rc;
}

int netconf_get_pool_stats(const netconf_cfg_t *cfg, dhcp_pool_stats_t *stats)
{
    struct nc_session *s;
    int rc;

    if (!stats) {
        fprintf(stderr, "[FAIL] [netconf_action] netconf_get_pool_stats got NULL stats\n");
        return -1;
    }

    s = session_open(cfg);
    if (!s)
        return -1;

    rc = send_get_pool_stats(s, stats);
    session_close(s);
    return rc;
}

int netconf_lookup_lease(const netconf_cfg_t *cfg,
                         const uint8_t mac[MAC_LEN],
                         uint32_t *ip)
{
    struct nc_session *s;
    int rc;

    if (!mac || !ip) {
        fprintf(stderr, "[FAIL] [netconf_action] netconf_lookup_lease got invalid arguments\n");
        return -1;
    }

    *ip = 0;
    s = session_open(cfg);
    if (!s)
        return -1;

    rc = send_lookup_lease(s, mac, ip);
    session_close(s);
    return rc;
}

int netconf_release_lease(const netconf_cfg_t *cfg,
                          const uint8_t mac[MAC_LEN],
                          uint32_t ip)
{
    struct nc_session *s;
    char xml[256];
    char ip_str[INET_ADDRSTRLEN] = "";
    int rc;

    if (!mac) {
        fprintf(stderr, "[FAIL] [netconf_action] netconf_release_lease got NULL MAC\n");
        return -1;
    }

    if (ip != 0) {
        struct in_addr a = { .s_addr = ip };
        if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str))) {
            fprintf(stderr, "[FAIL] [netconf_action] failed to format release IP\n");
            return -1;
        }
    }

    if (snprintf(xml, sizeof(xml),
                 "<release-lease xmlns=\"" NETCONF_YANG_NS "\">"
                 "<mac>%02x:%02x:%02x:%02x:%02x:%02x</mac>"
                 "<ip>%s</ip>"
                 "</release-lease>",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_str) >=
        (int)sizeof(xml)) {
        fprintf(stderr, "[FAIL] [netconf_action] release-lease XML too long\n");
        return -1;
    }

    s = session_open(cfg);
    if (!s)
        return -1;

    rc = send_generic_ok_rpc(s, xml, "release-lease");
    session_close(s);
    return rc;
}

int netconf_reset_pool(const netconf_cfg_t *cfg)
{
    struct nc_session *s;
    const char *xml = "<reset-pool xmlns=\"" NETCONF_YANG_NS "\"/>";
    int rc;

    s = session_open(cfg);
    if (!s)
        return -1;

    printf("netconf_action: resetting DHCP pool\n");
    rc = send_generic_ok_rpc(s, xml, "reset-pool");
    session_close(s);
    return rc;
}
