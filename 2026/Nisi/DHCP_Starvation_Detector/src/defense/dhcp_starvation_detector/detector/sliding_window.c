#include "sliding_window.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* =========================================================================
 * Counting Bloom Filter (Deri, tm2026.pdf slide 254)
 *
 * Uses k=3 independent hash functions obtained with FNV-1a and different seeds.
 * Each counter is uint8_t: in practice, the maximum reachable value is the
 * number of MACs that collide on the same position (on average
 * 3*15360/131072 ~= 0.35 per counter), so uint8_t is more than enough.
 * ========================================================================= */

static const uint32_t CBF_SEEDS[CBF_K] = {
    2166136261u,   /* FNV-1a offset basis standard */
    374761393u,    /* alternative seed */
    2246822519u    /* alternative seed */
};

static uint32_t cbf_hash(const uint8_t mac[6], int k)
{
    uint32_t h = CBF_SEEDS[k];
    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return h & CBF_MASK;
}

static int cbf_contains(const uint8_t *cbf, const uint8_t mac[6])
{
    for (int k = 0; k < CBF_K; k++)
        if (cbf[cbf_hash(mac, k)] == 0)
            return 0;
    return 1;
}

static void cbf_insert(uint8_t *cbf, const uint8_t mac[6])
{
    for (int k = 0; k < CBF_K; k++) {
        uint32_t pos = cbf_hash(mac, k);
        if (cbf[pos] < 255) cbf[pos]++;
    }
}

static void cbf_remove(uint8_t *cbf, const uint8_t mac[6])
{
    for (int k = 0; k < CBF_K; k++) {
        uint32_t pos = cbf_hash(mac, k);
        if (cbf[pos] > 0) cbf[pos]--;
    }
}

/* =========================================================================
 * HyperLogLog (Deri, tm2026.pdf slide 268-271)
 *
 * Simplified implementation faithful to the nDPI code shown on slide 270:
 *   index = hash >> (32 - bits)   <- first HLL_BITS bits = bucket index
 *   rank  = leading zeros of the remaining bits + 1
 *   regs[index] = max(regs[index], rank)
 *
 * Estimate with the correct alpha for m=1024 and linear-counting correction
 * for small cardinalities (zeros > 0 and estimate <= 2.5*m).
 * ========================================================================= */

static uint32_t hll_hash(const uint8_t mac[6])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return h;
}

static uint8_t hll_rank(uint32_t hash)
{
    /* Count leading zeros in the (32 - HLL_BITS) least significant bits. */
    uint32_t val = hash << HLL_BITS;
    uint8_t  r   = 1;
    uint8_t  max = 32 - HLL_BITS;
    while (r <= max && !(val & 0x80000000u)) { val <<= 1; r++; }
    return r;
}

static void hll_add(uint8_t *regs, const uint8_t mac[6])
{
    uint32_t h   = hll_hash(mac);
    uint32_t idx = h >> (32 - HLL_BITS);
    uint8_t  r   = hll_rank(h);
    if (r > regs[idx]) regs[idx] = r;
}

static double hll_estimate(const uint8_t *regs)
{
    /*
     * alpha for m=1024 (HLL_BITS=10): 0.7213 / (1 + 1.079/m)
     * From Deri slide 271 table: StdError = 1.04/sqrt(1024) ~= 3.25%
     */
    static const double alpha = 0.7213 / (1.0 + 1.079 / HLL_SIZE);

    double sum   = 0.0;
    int    zeros = 0;

    for (uint32_t i = 0; i < HLL_SIZE; i++) {
        sum += 1.0 / (double)(1u << regs[i]);
        if (!regs[i]) zeros++;
    }

    double est = alpha * (double)HLL_SIZE * (double)HLL_SIZE / sum;

    /* Linear-counting correction for small cardinalities. */
    if (est <= 2.5 * HLL_SIZE && zeros > 0)
        est = (double)HLL_SIZE * log((double)HLL_SIZE / (double)zeros);

    return est;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

int sw_init(sliding_window_t *sw, int num_slots)
{
    if (num_slots < 1)
        num_slots = 60;

    sw->slots = calloc((size_t)num_slots, sizeof(sw_slot_t));
    if (!sw->slots)
        return -1;

    sw->num_slots        = num_slots;
    sw->head             = 0;
    sw->total_discovers  = 0;
    sw->total_la_macs    = 0;
    memset(sw->cbf, 0, sizeof(sw->cbf));
    sw->slots[0].ts = time(NULL);
    return 0;
}

void sw_free(sliding_window_t *sw)
{
    free(sw->slots);
    sw->slots     = NULL;
    sw->num_slots = 0;
}

/*
 * Register a DHCP DISCOVER.
 *
 * The cap check comes before cbf_contains() for short-circuiting:
 * if the slot is full, the CBF is not touched, so CBF size remains strictly
 * bounded to num_slots * SW_MAX_MACS_PER_SLOT MACs.
 *
 * discovers and la_macs do not depend on the CBF: they are always exact.
 */
void sw_feed(sliding_window_t *sw, const uint8_t mac[6])
{
    sw_slot_t *cur = &sw->slots[sw->head];

    cur->discovers++;
    sw->total_discovers++;

    if (mac[0] & 0x02) {
        cur->la_macs++;
        sw->total_la_macs++;
    }

    if (cur->new_mac_count < SW_MAX_MACS_PER_SLOT && !cbf_contains(sw->cbf, mac)) {
        cbf_insert(sw->cbf, mac);
        hll_add(cur->hll, mac);
        memcpy(cur->new_macs[cur->new_mac_count++], mac, 6);
    }
}

/*
 * Advance the window by one second.
 *
 * Cost: O(SW_MAX_MACS_PER_SLOT * CBF_K) = O(768) to remove expiring-slot
 * MACs from the CBF. The CBF is never rebuilt from scratch.
 * Comparison with the previous version (ht_rebuild): O(768) vs O(15360).
 */
void sw_tick(sliding_window_t *sw)
{
    int       new_head = (sw->head + 1) % sw->num_slots;
    sw_slot_t *evicted = &sw->slots[new_head];

    /* Remove this slot's MACs from the CBF (Counting BF supports deletion). */
    for (uint32_t m = 0; m < evicted->new_mac_count; m++)
        cbf_remove(sw->cbf, evicted->new_macs[m]);

    sw->total_discovers -= evicted->discovers;
    sw->total_la_macs   -= evicted->la_macs;

    memset(evicted, 0, sizeof(*evicted));
    evicted->ts = time(NULL);

    sw->head = new_head;
}

uint32_t sw_total_discovers(const sliding_window_t *sw)
{
    return sw->total_discovers;
}

/*
 * HyperLogLog estimate of distinct MACs in the window.
 *
 * Each slot has its own HLL with the MACs first seen in that second.
 * Merge is performed by taking the maximum of each register across all HLLs:
 * this is the HLL union operation (correctness guaranteed by the structure).
 * Cost: O(num_slots * HLL_SIZE), called once per second for logging.
 */
uint32_t sw_estimate_unique_macs(const sliding_window_t *sw)
{
    uint8_t merged[HLL_SIZE];
    memset(merged, 0, sizeof(merged));

    for (int s = 0; s < sw->num_slots; s++)
        for (uint32_t i = 0; i < HLL_SIZE; i++)
            if (sw->slots[s].hll[i] > merged[i])
                merged[i] = sw->slots[s].hll[i];

    return (uint32_t)hll_estimate(merged);
}

float sw_la_ratio(const sliding_window_t *sw)
{
    if (sw->total_discovers == 0)
        return 0.0f;
    return (float)sw->total_la_macs / (float)sw->total_discovers;
}

float sw_last_sec_la_ratio(const sliding_window_t *sw)
{
    const sw_slot_t *prev =
        &sw->slots[(sw->head - 1 + sw->num_slots) % sw->num_slots];
    if (prev->discovers == 0)
        return 0.0f;
    return (float)prev->la_macs / (float)prev->discovers;
}

float sw_recent_la_ratio(const sliding_window_t *sw, int seconds,
                         uint32_t *sample_discovers)
{
    uint32_t discovers = 0;
    uint32_t la_macs = 0;

    if (seconds < 1)
        seconds = 1;
    if (seconds > sw->num_slots)
        seconds = sw->num_slots;

    for (int i = 1; i <= seconds; i++) {
        const sw_slot_t *slot =
            &sw->slots[(sw->head - i + sw->num_slots) % sw->num_slots];

        discovers += slot->discovers;
        la_macs += slot->la_macs;
    }

    if (sample_discovers)
        *sample_discovers = discovers;

    if (discovers == 0)
        return 0.0f;

    return (float)la_macs / (float)discovers;
}
