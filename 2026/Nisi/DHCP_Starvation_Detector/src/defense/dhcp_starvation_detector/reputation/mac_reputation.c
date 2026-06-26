#include "mac_reputation.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "../config/defense_config.h"

/* ---- Internal helpers --------------------------------------------------- */

static int cfg_int_clamped(const char *key, int fallback, int min, int max)
{
    int v = cfg_get_int(key, fallback);

    if (v < min)
        return min;
    if (v > max)
        return max;
    return v;
}

static int mr_min_discovers(void)
{
    return cfg_int_clamped("reputation.min_discovers", MR_MIN_DISCOVERS,
                           1, MR_MAX_DISCOVERS);
}

static int mr_max_discovers(void)
{
    return cfg_int_clamped("reputation.max_discovers", MR_MAX_DISCOVERS,
                           mr_min_discovers(), MR_MAX_DISCOVERS);
}

static int mr_min_interval(void)
{
    return cfg_int_clamped("reputation.min_interval_secs", MR_MIN_INTERVAL_S,
                           1, 3600);
}

static int mr_max_interval(void)
{
    return cfg_int_clamped("reputation.max_interval_secs", MR_MAX_INTERVAL_S,
                           mr_min_interval(), 86400);
}

static int mr_observation_window(void)
{
    return cfg_int_clamped("reputation.observation_window_secs",
                           MR_OBS_WINDOW_S, 1, 86400);
}

static int mr_pressure_entries(void)
{
    return cfg_int_clamped("reputation.pressure_entries", MR_PRESSURE_ENTRIES,
                           1, MR_MAX_ENTRIES);
}

static int mr_pressure_min_discovers(void)
{
    return cfg_int_clamped("reputation.pressure_min_discovers",
                           MR_PRESSURE_MIN_DISCOVERS,
                           mr_min_discovers(), MR_MAX_DISCOVERS);
}

static int mr_pressure_min_age(void)
{
    return cfg_int_clamped("reputation.pressure_min_age_secs",
                           MR_PRESSURE_MIN_AGE_S, 0, 86400);
}

static int mr_backoff_min_span(void)
{
    return cfg_int_clamped("reputation.backoff_min_span_secs",
                           MR_BACKOFF_MIN_SPAN_S, 0, 86400);
}

static int mr_backoff_growth_percent(void)
{
    return cfg_int_clamped("reputation.backoff_growth_percent",
                           MR_BACKOFF_GROWTH_PERCENT, 100, 1000);
}

static int mr_backoff_min_growth_steps(void)
{
    return cfg_int_clamped("reputation.backoff_min_growth_steps",
                           MR_BACKOFF_MIN_GROWTH_STEPS, 0,
                           MR_MAX_DISCOVERS - 2);
}

static int mr_max_tracking(void)
{
    return cfg_int_clamped("reputation.max_tracking", MR_MAX_TRACKING,
                           1, MR_MAX_ENTRIES);
}

static int mr_max_ready(void)
{
    return cfg_int_clamped("reputation.max_ready", MR_MAX_READY,
                           1, MR_MAX_ENTRIES);
}

static int mr_max_temp_whitelist(void)
{
    return cfg_int_clamped("reputation.max_temp_whitelist", MR_MAX_TEMP_WL,
                           1, MR_MAX_ENTRIES);
}

static int mr_promote_interval(void)
{
    return cfg_int_clamped("reputation.promote_interval_secs",
                           MR_PROMOTE_INTERVAL_S, 1, 86400);
}

static int mr_gate_slot_secs(void)
{
    return cfg_int_clamped("reputation.gate_slot_secs", MR_GATE_SLOT_S,
                           1, 86400);
}

static int mr_arp_retries(void)
{
    return cfg_int_clamped("reputation.arp_retries", MR_ARP_RETRIES, 1, 20);
}

static int mr_arp_retry_secs(void)
{
    return cfg_int_clamped("reputation.arp_retry_secs", MR_ARP_RETRY_S,
                           1, 300);
}

static int mr_lease_hint_arp_delay(void)
{
    return cfg_int_clamped("reputation.lease_hint_arp_delay_secs",
                           MR_LEASE_HINT_ARP_DELAY_S, 0, 300);
}

static int mr_ready_ttl(void)
{
    return cfg_int_clamped("reputation.ready_ttl_secs", MR_READY_TTL_S,
                           1, 86400);
}

static int mr_provisional_ttl(void)
{
    return cfg_int_clamped("reputation.provisional_ttl_secs",
                           MR_PROVISIONAL_TTL_S, 1, 86400);
}

static int mr_rejected_ttl(void)
{
    return cfg_int_clamped("reputation.rejected_ttl_secs", MR_REJECTED_TTL_S,
                           1, 86400);
}

static int mr_confirmed_ttl(void)
{
    return cfg_int_clamped("reputation.confirmed_ttl_secs", MR_CONFIRMED_TTL_S,
                           1, 86400);
}

static void mac_print(const uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static uint32_t mac_hash(const uint8_t mac[6], uint32_t seed)
{
    uint32_t h = 2166136261u ^ seed;

    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }

    h ^= h >> 16;
    h *= 2246822519u;
    h ^= h >> 13;
    h *= 3266489917u;
    h ^= h >> 16;
    return h;
}

static time_t gate_epoch(time_t ts)
{
    return ts / mr_gate_slot_secs();
}

static mr_gate_slot_t *gate_current_slot(mac_reputation_t *mr, time_t ts)
{
    time_t epoch = gate_epoch(ts);
    mr_gate_slot_t *slot = &mr->gate[epoch % MR_GATE_SLOTS];

    if (slot->epoch != epoch) {
        memset(slot->bits, 0, sizeof(slot->bits));
        slot->epoch = epoch;
    }

    return slot;
}

static int gate_slot_active(const mr_gate_slot_t *slot, time_t now)
{
    time_t epoch = gate_epoch(now);

    return slot->epoch != 0 &&
           slot->epoch <= epoch &&
           epoch - slot->epoch < MR_GATE_SLOTS;
}

static int gate_bit_is_set(const mr_gate_slot_t *slot, uint32_t bit)
{
    return (slot->bits[bit / 8] & (uint8_t)(1u << (bit % 8))) != 0;
}

static void gate_bit_set(mr_gate_slot_t *slot, uint32_t bit)
{
    slot->bits[bit / 8] |= (uint8_t)(1u << (bit % 8));
}

static int gate_seen(mac_reputation_t *mr, const uint8_t mac[6], time_t ts)
{
    gate_current_slot(mr, ts);

    for (int s = 0; s < MR_GATE_SLOTS; s++) {
        mr_gate_slot_t *slot = &mr->gate[s];

        if (!gate_slot_active(slot, ts))
            continue;

        int all_set = 1;
        for (uint32_t i = 0; i < 3; i++) {
            uint32_t bit = mac_hash(mac, 0x9e3779b9u * (i + 1)) % MR_GATE_BITS;
            if (!gate_bit_is_set(slot, bit)) {
                all_set = 0;
                break;
            }
        }

        if (all_set)
            return 1;
    }

    return 0;
}

static void gate_add(mac_reputation_t *mr, const uint8_t mac[6], time_t ts)
{
    mr_gate_slot_t *slot = gate_current_slot(mr, ts);

    for (uint32_t i = 0; i < 3; i++) {
        uint32_t bit = mac_hash(mac, 0x9e3779b9u * (i + 1)) % MR_GATE_BITS;
        gate_bit_set(slot, bit);
    }
}

static int find_candidate(mac_reputation_t *mr, const uint8_t mac[6])
{
    for (int i = 0; i < MR_CANDIDATES; i++)
        if (mr->candidates[i].used &&
            memcmp(mr->candidates[i].mac, mac, 6) == 0)
            return i;
    return -1;
}

static void forget_candidate(mac_reputation_t *mr, int idx)
{
    if (idx >= 0)
        memset(&mr->candidates[idx], 0, sizeof(mr->candidates[idx]));
}

static void remember_candidate(mac_reputation_t *mr,
                               const uint8_t mac[6], time_t ts)
{
    int idx = find_candidate(mr, mac);
    int is_new = (idx < 0);

    if (is_new) {
        time_t oldest = 0;

        for (int i = 0; i < MR_CANDIDATES; i++) {
            if (!mr->candidates[i].used) {
                idx = i;
                break;
            }

            if (oldest == 0 || mr->candidates[i].last_seen < oldest) {
                oldest = mr->candidates[i].last_seen;
                idx = i;
            }
        }

        memset(&mr->candidates[idx], 0, sizeof(mr->candidates[idx]));
        mr->candidates[idx].used = 1;
        memcpy(mr->candidates[idx].mac, mac, 6);
        mr->candidates[idx].first_seen = ts;
    }

    mr->candidates[idx].last_seen = ts;

    if (is_new) {
        printf("[reputation] ");
        mac_print(mac);
        printf("  CANDIDATE  first DISCOVER\n");
    }
}

static mr_entry_t *find_entry(mac_reputation_t *mr, const uint8_t mac[6])
{
    for (int i = 0; i < mr->count; i++)
        if (memcmp(mr->table[i].mac, mac, 6) == 0)
            return &mr->table[i];
    return NULL;
}

static int count_state(const mac_reputation_t *mr, mr_state_t state)
{
    int count = 0;

    for (int i = 0; i < mr->count; i++)
        if (mr->table[i].state == state)
            count++;

    return count;
}

static int count_temp_whitelist(const mac_reputation_t *mr)
{
    int count = 0;

    for (int i = 0; i < mr->count; i++) {
        mr_state_t s = mr->table[i].state;
        if (s == MR_PROVISIONAL || s == MR_ARP_PENDING)
            count++;
    }

    return count;
}

static int under_pressure(const mac_reputation_t *mr)
{
    return count_state(mr, MR_TRACKING) + count_state(mr, MR_READY)
           >= mr_pressure_entries();
}

static void delete_entry(mac_reputation_t *mr, int idx)
{
    if (!mr || idx < 0 || idx >= mr->count) {
        fprintf(stderr, "[FAIL] [reputation] delete_entry got invalid index\n");
        return;
    }

    mr_state_t state = mr->table[idx].state;

    if (mr->table[idx].arp_pid > 0) {
        if (kill(mr->table[idx].arp_pid, SIGKILL) != 0 && errno != ESRCH) {
            fprintf(stderr, "[WARN] [reputation] failed to kill ARP probe child %ld: %s\n",
                    (long)mr->table[idx].arp_pid, strerror(errno));
        }
        if (waitpid(mr->table[idx].arp_pid, NULL, 0) < 0 && errno != ECHILD) {
            fprintf(stderr, "[WARN] [reputation] failed to reap ARP probe child %ld: %s\n",
                    (long)mr->table[idx].arp_pid, strerror(errno));
        }
    }

    if ((state == MR_PROVISIONAL || state == MR_ARP_PENDING) &&
        mr->on_reject)
        mr->on_reject(mr->table[idx].mac, mr->table[idx].assigned_ip,
                      mr->cb_ctx);

    mr->table[idx] = mr->table[--mr->count];
}

static int find_weakest_tracking(mac_reputation_t *mr)
{
    int best = -1;
    int best_disc = 0;
    time_t best_ts = 0;

    for (int i = 0; i < mr->count; i++) {
        mr_entry_t *e = &mr->table[i];

        if (e->state != MR_TRACKING)
            continue;

        if (best == -1 ||
            e->disc_count < best_disc ||
            (e->disc_count == best_disc && e->last_seen < best_ts)) {
            best = i;
            best_disc = e->disc_count;
            best_ts = e->last_seen;
        }
    }

    return best;
}

static void enforce_tracking_quota(mac_reputation_t *mr)
{
    while (count_state(mr, MR_TRACKING) >= mr_max_tracking()) {
        int idx = find_weakest_tracking(mr);

        if (idx < 0)
            return;

        delete_entry(mr, idx);
    }
}

static void evict_one(mac_reputation_t *mr)
{
    /* Sacrifice weak states first. Candidates close to promotion are worth
     * more than MACs seen only once or already rejected. */
    int best = -1;
    int best_score = 1000000;
    time_t best_ts = 0;

    for (int i = 0; i < mr->count; i++) {
        mr_entry_t *e = &mr->table[i];
        int score;

        switch (e->state) {
            case MR_REJECTED:    score = 0; break;
            case MR_TRACKING:    score = 10 + e->disc_count; break;
            case MR_READY:       score = 40 + e->disc_count; break;
            case MR_PROVISIONAL: score = 300; break;
            case MR_ARP_PENDING: score = 400; break;
            case MR_CONFIRMED:   score = 500; break;
            default:             score = 0; break;
        }

        if (best == -1 ||
            score < best_score ||
            (score == best_score && e->last_seen < best_ts)) {
            best = i;
            best_score = score;
            best_ts = e->last_seen;
        }
    }

    if (best < 0) {
        fprintf(stderr, "[WARN] [reputation] eviction requested with empty table\n");
        return;
    }

    delete_entry(mr, best);
}

static mr_entry_t *create_entry(mac_reputation_t *mr,
                                const uint8_t mac[6], time_t ts)
{
    enforce_tracking_quota(mr);

    if (mr->count >= MR_MAX_ENTRIES)
        evict_one(mr);

    if (mr->count >= MR_MAX_ENTRIES) {
        fprintf(stderr, "[FAIL] [reputation] table full; cannot track new MAC\n");
        return NULL;
    }

    mr_entry_t *e = &mr->table[mr->count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->mac, mac, 6);
    e->state      = MR_TRACKING;
    e->first_seen = ts;
    e->last_seen  = ts;
    e->state_since = ts;
    e->arp_pid    = -1;
    return e;
}

static int ready_score(const mr_entry_t *e)
{
    int last_idx = e->disc_count - 1;
    time_t span = 0;

    if (last_idx > 0)
        span = e->ts[last_idx] - e->ts[0];

    if (span < 0)
        span = 0;

    return e->disc_count * 100 + (int)span;
}

static int find_weakest_ready(mac_reputation_t *mr)
{
    int best = -1;
    int best_score = 0;
    time_t best_ts = 0;

    for (int i = 0; i < mr->count; i++) {
        mr_entry_t *e = &mr->table[i];

        if (e->state != MR_READY)
            continue;

        int score = ready_score(e);

        if (best == -1 ||
            score < best_score ||
            (score == best_score && e->last_seen < best_ts)) {
            best = i;
            best_score = score;
            best_ts = e->last_seen;
        }
    }

    return best;
}

static int find_best_ready(mac_reputation_t *mr)
{
    int best = -1;
    int best_score = 0;
    time_t best_wait = 0;

    for (int i = 0; i < mr->count; i++) {
        mr_entry_t *e = &mr->table[i];

        if (e->state != MR_READY)
            continue;

        int score = ready_score(e);

        if (best == -1 ||
            score > best_score ||
            (score == best_score && e->state_since < best_wait)) {
            best = i;
            best_score = score;
            best_wait = e->state_since;
        }
    }

    return best;
}

static int backoff_pattern_ok(const mr_entry_t *e)
{
    int gaps = e->disc_count - 1;
    time_t min_gap;
    time_t max_gap;
    int growth_steps = 0;
    int required_growth_steps = mr_backoff_min_growth_steps();

    if (e->disc_count < mr_min_discovers())
        return 0;

    if (gaps < 2)
        return 1;

    min_gap = e->ts[1] - e->ts[0];
    max_gap = min_gap;

    for (int i = 2; i < e->disc_count; i++) {
        time_t prev_gap = e->ts[i - 1] - e->ts[i - 2];
        time_t gap = e->ts[i] - e->ts[i - 1];

        if (gap < min_gap)
            min_gap = gap;
        if (gap > max_gap)
            max_gap = gap;

        if (gap * 100 >= prev_gap * mr_backoff_growth_percent())
            growth_steps++;
    }

    if (e->ts[e->disc_count - 1] - e->ts[0] < mr_backoff_min_span())
        return 0;

    if (required_growth_steps > 0 &&
        growth_steps < required_growth_steps)
        return 0;

    if (min_gap > 0 &&
        max_gap * 100 < min_gap * mr_backoff_growth_percent())
        return 0;

    return 1;
}

static int heuristic_ok(const mac_reputation_t *mr, const mr_entry_t *e)
{
    int pressure = under_pressure(mr);
    int min_discovers = pressure ? mr_pressure_min_discovers() : mr_min_discovers();

    if (e->disc_count < min_discovers || e->disc_count > mr_max_discovers())
        return 0;

    for (int i = 1; i < e->disc_count; i++) {
        time_t gap = e->ts[i] - e->ts[i - 1];
        if (gap < mr_min_interval() || gap > mr_max_interval())
            return 0;
    }

    if (!backoff_pattern_ok(e))
        return 0;

    if (pressure &&
        e->ts[e->disc_count - 1] - e->ts[0] < mr_pressure_min_age())
        return 0;

    return 1;
}

#ifdef __linux__
static int native_arp_probe(const uint8_t expected_mac[6],
                            uint32_t target_ip,
                            const char *iface)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe socket failed: %s\n",
                strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe SIOCGIFINDEX failed on %s: %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe SIOCGIFHWADDR failed on %s: %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }
    uint8_t local_mac[ETH_ALEN];
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe SIOCGIFADDR failed on %s: %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }
    uint32_t local_ip =
        ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    struct sockaddr_ll bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex = ifindex;

    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe bind failed on %s: %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }

    struct {
        struct ether_header eth;
        struct ether_arp arp;
    } pkt;

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth.ether_dhost, 0xff, ETH_ALEN);
    memcpy(pkt.eth.ether_shost, local_mac, ETH_ALEN);
    pkt.eth.ether_type = htons(ETHERTYPE_ARP);

    pkt.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    pkt.arp.ea_hdr.ar_hln = ETH_ALEN;
    pkt.arp.ea_hdr.ar_pln = 4;
    pkt.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt.arp.arp_sha, local_mac, ETH_ALEN);
    memcpy(pkt.arp.arp_spa, &local_ip, 4);
    memcpy(pkt.arp.arp_tpa, &target_ip, 4);

    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof(dst));
    dst.sll_family = AF_PACKET;
    dst.sll_ifindex = ifindex;
    dst.sll_halen = ETH_ALEN;
    memset(dst.sll_addr, 0xff, ETH_ALEN);

    if (sendto(fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe send failed on %s: %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }

    time_t deadline = time(NULL) + 2;
    while (time(NULL) <= deadline) {
        fd_set rfds;
        struct timeval tv;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[WARN] [reputation] ARP probe select failed: %s\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
        if (rc == 0)
            continue;

        uint8_t buf[1600];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[WARN] [reputation] ARP probe recv failed: %s\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
        if (n < (ssize_t)(sizeof(struct ether_header) +
                          sizeof(struct ether_arp)))
            continue;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
            continue;

        struct ether_arp *arp =
            (struct ether_arp *)(buf + sizeof(struct ether_header));

        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY)
            continue;
        if (memcmp(arp->arp_spa, &target_ip, 4) != 0)
            continue;
        if (memcmp(arp->arp_sha, expected_mac, ETH_ALEN) != 0)
            continue;

        close(fd);
        return 0;
    }

    close(fd);
    return 1;
}
#endif

static void arp_probe_async(mr_entry_t *e, const char *iface)
{
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = e->assigned_ip };
    if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
        snprintf(ip_str, sizeof(ip_str), "unknown");

    pid_t pid = fork();
    if (pid == 0) {
#ifdef __linux__
        int rc = native_arp_probe(e->mac, e->assigned_ip, iface);
        _exit(rc == 0 ? 0 : rc < 0 ? 2 : 1);
#else
        char *const argv[] = {
            "arping", "-c", "1", "-w", "2", "-q",
            "-I", (char *)iface, ip_str, NULL
        };
        execvp("arping", argv);
        fprintf(stderr, "[WARN] [reputation] execvp arping failed: %s\n",
                strerror(errno));
        _exit(1);
#endif
    }

    if (pid < 0) {
        fprintf(stderr, "[WARN] [reputation] ARP probe fork failed: %s\n",
                strerror(errno));
        e->arp_pid = -1;
        e->arp_tries++;
        e->arp_next = time(NULL) + mr_arp_retry_secs();
        return;
    }

    e->arp_pid = pid;
}

static void reject_entry(mr_entry_t *e, const char *reason)
{
    printf("[reputation] ");
    mac_print(e->mac);
    printf("  REJECTED  discover=%d  reason=%s\n",
           e->disc_count, reason);

    e->state = MR_REJECTED;
    e->state_since = e->last_seen;
}

static void reset_tracking(mr_entry_t *e, time_t ts)
{
    memset(e->ts, 0, sizeof(e->ts));
    e->disc_count = 1;
    e->ts[0] = ts;
    e->first_seen = ts;
    e->last_seen = ts;
    e->state_since = ts;
}

static int mark_ready(mac_reputation_t *mr, mr_entry_t *e, time_t now)
{
    uint8_t mac[6];
    memcpy(mac, e->mac, sizeof(mac));

    if (count_state(mr, MR_READY) >= mr_max_ready()) {
        int weakest = find_weakest_ready(mr);
        int new_score = ready_score(e);
        int weakest_score = weakest >= 0 ? ready_score(&mr->table[weakest]) : -1;

        if (weakest < 0 || new_score < weakest_score) {
            int current = (int)(e - mr->table);

            printf("[reputation] ");
            mac_print(e->mac);
            printf("  dropped before READY  reason=ready-queue-full\n");

            delete_entry(mr, current);
            return 0;
        }

        printf("[reputation] ");
        mac_print(mr->table[weakest].mac);
        printf("  evicted from READY  reason=weaker-candidate\n");
        delete_entry(mr, weakest);

        e = find_entry(mr, mac);
        if (!e)
            return 0;
    }

    e->state = MR_READY;
    e->state_since = now;

    printf("[reputation] ");
    mac_print(e->mac);
    printf("  READY  discover=%d  waiting for promotion budget\n",
           e->disc_count);

    return 1;
}

static void withdraw_temp_whitelist(mac_reputation_t *mr, mr_entry_t *e,
                                    time_t now, const char *reason)
{
    printf("[reputation] ");
    mac_print(e->mac);
    printf("  TEMP-WHITELIST removed  reason=%s\n", reason);

    e->state = MR_REJECTED;
    e->state_since = now;

    if (mr->on_reject)
        mr->on_reject(e->mac, e->assigned_ip, mr->cb_ctx);
}

static void persist_confirmed(mac_reputation_t *mr, const uint8_t mac[6])
{
    if (!mr->confirmed_wl_enabled)
        return;

    int rc = whitelist_add(&mr->confirmed_wl, mac, "reputation-confirmed");

    printf("[reputation] ");
    mac_print(mac);

    if (rc == 0)
        printf("  saved to %s\n", mr->confirmed_wl.filepath);
    else if (rc == 1)
        printf("  already present in %s\n", mr->confirmed_wl.filepath);
    else
        printf("  [FAIL] failed to save to %s\n", mr->confirmed_wl.filepath);
}

static void promote_ready_one(mac_reputation_t *mr, time_t now)
{
    if (now < mr->next_promotion)
        return;

    if (count_temp_whitelist(mr) >= mr_max_temp_whitelist())
        return;

    int idx = find_best_ready(mr);
    if (idx < 0)
        return;

    mr_entry_t *e = &mr->table[idx];
    e->state = MR_PROVISIONAL;
    e->state_since = now;
    e->last_seen = now;
    mr->next_promotion = now + mr_promote_interval();

    printf("[reputation] ");
    mac_print(e->mac);
    printf("  TEMP-WHITELIST  discover=%d  waiting for ACK\n",
           e->disc_count);

    if (mr->on_promote)
        mr->on_promote(e->mac, mr->cb_ctx);
}

/* ---- Public API --------------------------------------------------------- */

void mr_init(mac_reputation_t *mr,
             const char       *iface,
             mr_promote_cb     on_promote,
             mr_confirm_cb     on_confirm,
             mr_reject_cb      on_reject,
             void             *ctx)
{
    if (!mr)
        return;

    memset(mr, 0, sizeof(*mr));
    if (iface)
        strncpy(mr->iface, iface, sizeof(mr->iface) - 1);
    mr->on_promote = on_promote;
    mr->on_confirm = on_confirm;
    mr->on_reject  = on_reject;
    mr->cb_ctx     = ctx;
}

int mr_enable_confirmed_whitelist(mac_reputation_t *mr, const char *path)
{
    if (!mr) {
        fprintf(stderr, "[FAIL] [reputation] missing reputation context\n");
        return -1;
    }

    if (whitelist_load(&mr->confirmed_wl, path) != 0) {
        mr->confirmed_wl_enabled = 0;
        return -1;
    }

    mr->confirmed_wl_enabled = 1;
    printf("[reputation] confirmed whitelist db: %s (%d MACs loaded)\n",
           mr->confirmed_wl.filepath, mr->confirmed_wl.count);
    return 0;
}

void mr_feed_discover(mac_reputation_t *mr, const uint8_t mac[6], time_t ts)
{
    if (!mr || !mac)
        return;

    mr_entry_t *e = find_entry(mr, mac);
    int seen_before = gate_seen(mr, mac, ts);

    if (!e) {
        int cand_idx = find_candidate(mr, mac);

        if (!seen_before && cand_idx < 0) {
            gate_add(mr, mac, ts);
            remember_candidate(mr, mac, ts);
            return;
        }

        if (cand_idx >= 0) {
            mr_candidate_t *cand = &mr->candidates[cand_idx];
            time_t gap = ts - cand->last_seen;

            gate_add(mr, mac, ts);

            if (gap < mr_min_interval() ||
                gap > mr_max_interval() ||
                ts - cand->first_seen > mr_observation_window()) {
                cand->first_seen = ts;
                cand->last_seen = ts;
                return;
            }

            e = create_entry(mr, mac, cand->last_seen);
            if (!e)
                return;
            e->ts[0] = cand->last_seen;
            e->ts[1] = ts;
            e->disc_count = 2;
            e->first_seen = cand->last_seen;
            e->last_seen = ts;
            e->state_since = ts;
            forget_candidate(mr, cand_idx);

            printf("[reputation] ");
            mac_print(mac);
            printf("  TRACKING  discover=%d  gap=%lds\n",
                   e->disc_count, (long)gap);
        } else {
            gate_add(mr, mac, ts);
            e = create_entry(mr, mac, ts);
            if (!e)
                return;
            e->ts[0] = ts;
            e->disc_count = 1;

            printf("[reputation] ");
            mac_print(mac);
            printf("  TRACKING  discover=%d\n", e->disc_count);
        }
    } else {
        gate_add(mr, mac, ts);
        e->last_seen = ts;

        if (e->state == MR_READY) {
            if (e->disc_count > 0) {
                int last_idx = e->disc_count - 1;
                if (last_idx >= MR_MAX_DISCOVERS)
                    last_idx = MR_MAX_DISCOVERS - 1;

                time_t gap = ts - e->ts[last_idx];

                if (gap >= mr_min_interval() &&
                    gap <= mr_max_interval() &&
                    e->disc_count < mr_max_discovers())
                    e->ts[e->disc_count++] = ts;
            }
            return;
        }

        if (e->state != MR_TRACKING)
            return;

        if (ts - e->first_seen > mr_observation_window()) {
            reset_tracking(e, ts);
            return;
        }

        if (e->disc_count > 0) {
            int last_idx = e->disc_count - 1;
            if (last_idx >= MR_MAX_DISCOVERS)
                last_idx = MR_MAX_DISCOVERS - 1;

            time_t gap = ts - e->ts[last_idx];

            if (gap < mr_min_interval())
                return;

            if (gap > mr_max_interval()) {
                reset_tracking(e, ts);
                return;
            }
        }

        if (e->disc_count >= mr_max_discovers()) {
            reject_entry(e, "too-many-discovers");
            return;
        }

        e->ts[e->disc_count++] = ts;

        printf("[reputation] ");
        mac_print(mac);
        printf("  TRACKING  discover=%d\n", e->disc_count);
    }

    if (e->disc_count < mr_min_discovers())
        return;

    if (heuristic_ok(mr, e))
        mark_ready(mr, e, ts);
}

void mr_feed_lease_hint(mac_reputation_t *mr, const uint8_t mac[6],
                        uint32_t ip, time_t ts, const char *source)
{
    if (!mr || !mac)
        return;

    mr_entry_t *e = find_entry(mr, mac);
    if (!e || e->state != MR_PROVISIONAL || ip == 0)
        return;

    int delay = (source && strcmp(source, "ACK") == 0)
                ? 0
                : mr_lease_hint_arp_delay();
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = ip };
    if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
        snprintf(ip_str, sizeof(ip_str), "unknown");

    e->assigned_ip = ip;
    e->state       = MR_ARP_PENDING;
    e->last_seen   = ts;
    e->state_since = ts;
    e->arp_tries   = 0;
    e->arp_next    = ts + delay;
    e->arp_pid     = -1;

    printf("[reputation] ");
    mac_print(mac);
    if (delay == 0) {
        printf("  %s  IP=%-15s  ARP probes started\n",
               source ? source : "LEASE-HINT", ip_str);
    } else {
        printf("  %s  IP=%-15s  ARP probes scheduled in %ds\n",
               source ? source : "LEASE-HINT", ip_str, delay);
    }
}

void mr_feed_ack(mac_reputation_t *mr, const uint8_t mac[6],
                 uint32_t yiaddr, time_t ts)
{
    mr_feed_lease_hint(mr, mac, yiaddr, ts, "ACK");
}

void mr_tick(mac_reputation_t *mr, time_t now)
{
    if (!mr)
        return;

    for (int c = 0; c < MR_CANDIDATES; c++) {
        if (mr->candidates[c].used &&
            now - mr->candidates[c].last_seen > mr_observation_window())
            memset(&mr->candidates[c], 0, sizeof(mr->candidates[c]));
    }

    for (int i = 0; i < mr->count; ) {
        mr_entry_t *e = &mr->table[i];

        /* Evict expired TRACKING entries. */
        if (e->state == MR_TRACKING &&
            now - e->first_seen > mr_observation_window()) {
            delete_entry(mr, i);
            continue;
        }

        if (e->state == MR_READY &&
            now - e->state_since > mr_ready_ttl()) {
            printf("[reputation] ");
            mac_print(e->mac);
            printf("  READY timeout, removed\n");
            delete_entry(mr, i);
            continue;
        }

        if (e->state == MR_PROVISIONAL &&
            now - e->state_since > mr_provisional_ttl()) {
            withdraw_temp_whitelist(mr, e, now, "ack-timeout");
        }

        if (e->state == MR_REJECTED &&
            now - e->state_since > mr_rejected_ttl()) {
            delete_entry(mr, i);
            continue;
        }

        if (e->state == MR_CONFIRMED &&
            now - e->state_since > mr_confirmed_ttl()) {
            delete_entry(mr, i);
            continue;
        }

        if (e->state == MR_ARP_PENDING) {

            /* Collect arping result if already started. */
            if (e->arp_pid > 0) {
                int   status;
                pid_t done = waitpid(e->arp_pid, &status, WNOHANG);

                if (done == e->arp_pid) {
                    e->arp_pid = -1;
                    char ip_str[INET_ADDRSTRLEN];
                    struct in_addr a = { .s_addr = e->assigned_ip };
                    if (!inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str)))
                        snprintf(ip_str, sizeof(ip_str), "unknown");

                    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                        printf("[reputation] ");
                        mac_print(e->mac);
                        printf("  ARP OK   IP=%-15s  CONFIRMED\n", ip_str);
                        e->state = MR_CONFIRMED;
                        e->state_since = now;
                        persist_confirmed(mr, e->mac);
                        if (mr->on_confirm)
                            mr->on_confirm(e->mac, e->assigned_ip, mr->cb_ctx);
                    } else {
                        if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
                            printf("[reputation] ");
                            mac_print(e->mac);
                            printf("  ARP probe internal error; retrying\n");
                        }
                        e->arp_tries++;
                        if (e->arp_tries >= mr_arp_retries()) {
                            (void)ip_str;
                            withdraw_temp_whitelist(mr, e, now, "arp-failed");
                        } else {
                            e->arp_next = now + mr_arp_retry_secs();
                        }
                    }
                } else if (done < 0) {
                    fprintf(stderr,
                            "[WARN] [reputation] waitpid failed for ARP probe child %ld: %s\n",
                            (long)e->arp_pid, strerror(errno));
                    e->arp_pid = -1;
                    e->arp_tries++;
                    if (e->arp_tries >= mr_arp_retries()) {
                        withdraw_temp_whitelist(mr, e, now, "arp-probe-error");
                    } else {
                        e->arp_next = now + mr_arp_retry_secs();
                    }
                }
            }

            /* Start a new attempt if no child process is active. */
            if (e->state == MR_ARP_PENDING &&
                e->arp_pid <= 0 && now >= e->arp_next) {
                printf("[reputation] ");
                mac_print(e->mac);
                printf("  ARP probe %d/%d\n",
                       e->arp_tries + 1, mr_arp_retries());
                arp_probe_async(e, mr->iface);
            }
        }

        i++;
    }

    promote_ready_one(mr, now);
}

const char *mr_state_str(mr_state_t s)
{
    switch (s) {
        case MR_TRACKING:    return "TRACKING";
        case MR_READY:       return "READY";
        case MR_PROVISIONAL: return "PROVISIONAL";
        case MR_ARP_PENDING: return "ARP_PENDING";
        case MR_CONFIRMED:   return "CONFIRMED";
        case MR_REJECTED:    return "REJECTED";
        default:             return "UNKNOWN";
    }
}
