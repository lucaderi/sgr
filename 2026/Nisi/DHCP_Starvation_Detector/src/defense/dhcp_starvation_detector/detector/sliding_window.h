#ifndef SLIDING_WINDOW_H
#define SLIDING_WINDOW_H

#include <stdint.h>
#include <time.h>

/*
 * sliding_window - Feature 1 of the detection engine.
 *
 * Data structures used (from Deri, tm2026.pdf):
 *
 *  - Counting Bloom Filter (slide 254): answers "is this MAC already in the
 *    window?" in constant O(k), supports deletion when a slot expires, and
 *    does not degrade under attack unlike open addressing.
 *
 *  - HyperLogLog (slides 268-271): one per slot, estimates how many distinct
 *    MACs were seen in that second. The total window is computed by merging
 *    the N HLLs, taking the maximum register by register (approximate union).
 *
 * Advantages over the previous open-addressing hash table:
 *   - CBF: always O(k=3), no linear probing, no degradation under attack
 *   - HLL: estimated cardinality with 3.25% error using only 1 KB per slot
 *   - sw_tick(): O(256*3) instead of O(15360) for the old ht_rebuild
 *
 * The window length (number of slots = seconds) is set at runtime via
 * sw_init(sw, num_slots) so it can be read from the config file.
 *
 * Typical usage:
 *   sw_init(&sw, 60);           // 60-second window
 *   sw_feed(&sw, mac);          // pcap callback, for every DHCP DISCOVER
 *   sw_tick(&sw);               // SIGALRM, every second
 *   sw_total_discovers(&sw);    // input leaky bucket / Z-score
 *   sw_estimate_unique_macs();  // HLL estimate, Feature 2 / logging
 *   sw_la_ratio(&sw);           // Feature 5
 *   sw_free(&sw);               // release heap memory
 */

#define SW_MAX_MACS_PER_SLOT 256

/* ---- Counting Bloom Filter (Deri, slide 254) ----------------------------
 *
 * m = 2^17 = 131072 uint8_t counters = 128 KB
 * k = 3 hash functions (distinct FNV-1a seeds)
 * n_max = 60 * 256 = 15360 MACs in the window
 * False-positive rate: (1 - e^(-k*n/m))^k ~= 2.6%
 *   -> about one new MAC in 40 is incorrectly considered already seen
 *   -> slight unique_macs undercount, negligible for detection
 */
#define CBF_BITS  17
#define CBF_SIZE  (1u << CBF_BITS)   /* 131072 */
#define CBF_MASK  (CBF_SIZE - 1u)
#define CBF_K     3

/* ---- HyperLogLog (Deri, slide 268-271) ----------------------------------
 *
 * bits = 10 -> 1024 buckets per slot, StdError = 1.04/sqrt(1024) ~= 3.25%
 * Memory per slot: 1024 bytes = 1 KB; for 60 slots: 60 KB
 * Window cardinality estimate: merge the 60 HLLs (max register by register)
 * Requires -lm at link time (uses log() in sw_estimate_unique_macs).
 */
#define HLL_BITS  10
#define HLL_SIZE  (1u << HLL_BITS)   /* 1024 */

/* ---- Data structures --------------------------------------------------- */

typedef struct {
    uint32_t discovers;                    /* DISCOVERs received in this slot */
    uint32_t la_macs;                      /* DISCOVERs with LA-bit (mac[0] & 0x02) */
    time_t   ts;

    uint8_t  new_macs[SW_MAX_MACS_PER_SLOT][6]; /* MACs inserted into the CBF by this slot */
    uint32_t new_mac_count;

    uint8_t  hll[HLL_SIZE];               /* HLL for MACs first seen here */
} sw_slot_t;

typedef struct {
    sw_slot_t *slots;                     /* heap-allocated array of num_slots entries */
    int        num_slots;
    int        head;

    uint32_t  total_discovers;
    uint32_t  total_la_macs;

    uint8_t   cbf[CBF_SIZE];              /* Counting Bloom Filter shared across the window */
} sliding_window_t;

/* ---- Public API --------------------------------------------------------- */

/* Allocate num_slots slot entries. Returns 0 on success, -1 on malloc failure. */
int      sw_init(sliding_window_t *sw, int num_slots);
void     sw_free(sliding_window_t *sw);
void     sw_feed(sliding_window_t *sw, const uint8_t mac[6]);
void     sw_tick(sliding_window_t *sw);

uint32_t sw_total_discovers(const sliding_window_t *sw);

/* HyperLogLog estimate of distinct MACs in the window (+/-3.25%). */
uint32_t sw_estimate_unique_macs(const sliding_window_t *sw);

/* LA-MAC / total DISCOVER ratio in the window [0.0..1.0]. */
float    sw_la_ratio(const sliding_window_t *sw);

/* LA-MAC / DISCOVER ratio in the last second [0.0..1.0].
 * Drops to zero immediately when traffic stops; use for F5 instead of
 * sw_la_ratio() to avoid the 60-second post-attack tail. */
float    sw_last_sec_la_ratio(const sliding_window_t *sw);

/* LA-MAC / DISCOVER ratio over the last N completed seconds [0.0..1.0].
 * This smooths short packet scheduling gaps while still decaying quickly.
 * If sample_discovers is non-NULL, it receives the DISCOVER count used. */
float    sw_recent_la_ratio(const sliding_window_t *sw, int seconds,
                            uint32_t *sample_discovers);

#endif /* SLIDING_WINDOW_H */
