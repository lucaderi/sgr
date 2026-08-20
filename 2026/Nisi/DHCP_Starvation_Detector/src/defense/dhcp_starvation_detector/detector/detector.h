#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdint.h>

#include "sliding_window.h"
#include "leaky_bucket.h"
#include "adaptive_score.h"
#include "../rrd/rrd_stats.h"

#define DETECTOR_POOL_HISTORY_SAMPLES    64u

typedef struct {
    uint32_t ts;
    uint32_t used;
    uint32_t total;
} detector_pool_sample_t;

/*
 * detector - DHCP starvation detection engine.
 *
 * Combines five features into one aggregate score:
 *   F2  Unique MACs    - fires when the 60s window contains many distinct MACs
 *   F3  Leaky Bucket   - fires if the rate exceeds the absolute threshold
 *   F4  Z-score / EMA  - fires if the rate exceeds the adaptive baseline
 *   F5  LA-bit ratio   - fires if locally-administered MACs exceed the threshold
 *   F6  Pool pressure  - fires if the DHCP pool is being exhausted slowly
 *
 *   score >= configured threshold or F6=1  ->  *** ATTACK ***
 *
 * Interface:
 *   detector_init()         - initializes the structure and RRD database
 *   detector_feed()         - call from the pcap callback for every DHCP DISCOVER
 *   detector_tick()         - call every second from the SIGALRM handler
 *   detector_rrd_pending()  - returns 1 if there is an RRD sample to write
 *   detector_rrd_flush()    - writes the sample to disk; call from the main loop
 *
 * Do not declare on the stack: ~350 KB, mostly from sliding_window_t.
 * Use a global or static variable.
 */
typedef struct {
    sliding_window_t  sw;
    leaky_bucket_t    lb;
    adaptive_score_t  as;

    uint32_t          cur_sec_discovers;  /* DISCOVERs in the last second         */
    int               alert_hold;         /* remaining alert-hold seconds         */
    int               last_attack;        /* last tick attack decision            */

    uint32_t          pool_used;
    uint32_t          pool_total;
    uint32_t          pool_growth;
    float             pool_usage;
    float             pool_growth_per_sec;
    uint32_t          pool_tte_secs;
    int               pool_alert_hold;
    detector_pool_sample_t pool_samples[DETECTOR_POOL_HISTORY_SAMPLES];
    uint32_t          pool_sample_next;
    uint32_t          pool_sample_count;

    /* RRD snapshot: written by detector_tick (SIGALRM), read by detector_rrd_flush. */
    unsigned          rrd_tick;
    volatile int      rrd_due;
    volatile uint32_t rrd_snap_discovers;
    volatile uint32_t rrd_snap_unique_macs;
    volatile float    rrd_snap_la_ratio;
    volatile double   rrd_snap_bucket_tokens;
    volatile double   rrd_snap_bucket_capacity;
    volatile double   rrd_snap_baseline_ema;
    volatile double   rrd_snap_baseline_dev;
    volatile uint32_t rrd_snap_pool_used;
    volatile uint32_t rrd_snap_pool_total;
    volatile float    rrd_snap_pool_usage_pct;
    volatile uint32_t rrd_snap_pool_growth;
    volatile uint32_t rrd_snap_pool_tte_secs;
} detector_t;

/* Initialize the detector and create the RRD database.
 * Returns 0 on success, -1 on fatal initialization error. */
int detector_init(detector_t *d);

/*
 * Register a DHCP DISCOVER: update the sliding window and per-second counter.
 * Call from the pcap callback for every DISCOVER packet.
 */
void detector_feed(detector_t *d, const uint8_t mac[6]);

/*
 * Update the DHCP pool snapshot.
 * Call from the main loop after reading the DHCP backend lease state.
 */
void detector_pool_update(detector_t *d, uint32_t used, uint32_t total);

/*
 * Advance the window by one second, compute the score, and print the status.
 * Safe to call from a SIGALRM handler (does not invoke system()).
 */
void detector_tick(detector_t *d);

/* Return 1 if there is an RRD sample to write, 0 otherwise. */
int  detector_rrd_pending(const detector_t *d);

/*
 * Write the RRD sample to disk.
 * Call from the main loop (not from the signal handler),
 * only when detector_rrd_pending() returns 1.
 */
void detector_rrd_flush(detector_t *d);

/* Return 1 while the detector alert is active, 0 otherwise. */
int detector_attack_active(const detector_t *d);

/* Seconds between pool-occupancy polls (detector.pool_poll_secs). */
uint32_t detector_pool_poll_secs(void);

#endif /* DETECTOR_H */
