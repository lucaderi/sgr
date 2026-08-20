#ifndef RRD_STATS_H
#define RRD_STATS_H

#include <stdint.h>

/*
 * rrd_stats - detector time-series exporter.
 *
 * Writes DHCP metrics to a Round Robin Database (RRDtool) at the configured
 * step interval.
 * The .rrd file has a fixed size and overwrites older data, so it never grows.
 *
 * Schema RRD:
 *   DS:discovers       GAUGE  - total DISCOVERs in the detector window
 *   DS:unique_macs     GAUGE  - estimated distinct MACs (HLL)
 *   DS:la_ratio        GAUGE  - LA-bit ratio [0..1] over the detector window
 *   DS:bucket_tokens   GAUGE  - current leaky-bucket token level
 *   DS:bucket_capacity GAUGE  - configured leaky-bucket capacity
 *   DS:baseline_ema    GAUGE  - adaptive-score EMA baseline
 *   DS:baseline_dev    GAUGE  - adaptive-score deviation
 *   DS:pool_used       GAUGE  - active DHCP leases
 *   DS:pool_total      GAUGE  - total DHCP pool size
 *   DS:pool_usage_pct  GAUGE  - DHCP pool usage percent [0..100]
 *   DS:pool_growth     GAUGE  - lease growth over the configured pool history
 *   DS:pool_tte_secs   GAUGE  - projected time to exhaustion in seconds
 *
 *   RRA:AVERAGE  - average over the configured archive horizon
 *   RRA:MAX      - maximum over the configured archive horizon
 *                  (Deri, rrd_tutorial: without MAX, bursts disappear in the average)
 *
 * Dependencies: requires `rrdtool` installed in PATH.
 *   sudo apt install rrdtool
 *
 * Typical usage:
 *   rrd_init(path);
 *   rrd_update(path, &sample);
 */

typedef struct {
    uint32_t discovers;
    uint32_t unique_macs;
    float    la_ratio;
    double   bucket_tokens;
    double   bucket_capacity;
    double   baseline_ema;
    double   baseline_dev;
    uint32_t pool_used;
    uint32_t pool_total;
    float    pool_usage_pct;
    uint32_t pool_growth;
    uint32_t pool_tte_secs;
} rrd_sample_t;

/*
 * Create the .rrd file if it does not already exist.
 * Call only once at startup.
 */
void rrd_init(const char *path);

/*
 * Write one sample.
 * sample contains one complete detector snapshot.
 */
void rrd_update(const char *path, const rrd_sample_t *sample);

#endif /* RRD_STATS_H */
