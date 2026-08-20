#include "detector.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../config/defense_config.h"

static uint32_t detector_score_threshold(void)
{
    return cfg_get_u32("detector.score_threshold", 2u);
}

static uint32_t detector_alert_hold_secs(void)
{
    return cfg_get_u32("detector.alert_hold_secs", 5u);
}

static uint32_t detector_pool_alert_hold_secs(void)
{
    return cfg_get_u32("detector.pool_alert_hold_secs", 30u);
}

static uint32_t detector_rrd_step_secs(void)
{
    return cfg_get_u32("rrd.step_secs",
                       cfg_get_u32("detector.rrd.step_secs", 10u));
}

uint32_t detector_pool_poll_secs(void)
{
    return cfg_get_u32("detector.pool_poll_secs", 5u);
}

int detector_init(detector_t *d)
{
    (void)cfg_load_default();

    if (sw_init(&d->sw, cfg_get_int("detector.window_secs", 60)) != 0) {
        fprintf(stderr, "[FAIL] detector_init: sw_init: out of memory\n");
        return -1;
    }
    lb_init(&d->lb,
            cfg_get_double("detector.leaky_bucket.capacity", 60.0),
            cfg_get_double("detector.leaky_bucket.refill_per_sec", 2.0));
    as_init(&d->as,
            cfg_get_double("detector.adaptive_score.alpha", 0.10),
            cfg_get_double("detector.adaptive_score.gamma", 0.10),
            cfg_get_double("detector.adaptive_score.delta", 1.50),
            cfg_get_u32("detector.adaptive_score.warmup", 120u));

    d->cur_sec_discovers    = 0;
    d->alert_hold           = 0;
    d->last_attack          = 0;
    d->pool_used            = 0;
    d->pool_total           = 0;
    d->pool_growth          = 0;
    d->pool_usage           = 0.0f;
    d->pool_growth_per_sec  = 0.0f;
    d->pool_tte_secs        = 0;
    d->pool_alert_hold      = 0;
    d->pool_sample_next     = 0;
    d->pool_sample_count    = 0;
    memset(d->pool_samples, 0, sizeof(d->pool_samples));
    d->rrd_tick             = 0;
    d->rrd_due              = 0;
    d->rrd_snap_discovers   = 0;
    d->rrd_snap_unique_macs = 0;
    d->rrd_snap_la_ratio    = 0.0f;
    d->rrd_snap_bucket_tokens = 0.0;
    d->rrd_snap_bucket_capacity = 0.0;
    d->rrd_snap_baseline_ema = 0.0;
    d->rrd_snap_baseline_dev = 0.0;
    d->rrd_snap_pool_used = 0;
    d->rrd_snap_pool_total = 0;
    d->rrd_snap_pool_usage_pct = 0.0f;
    d->rrd_snap_pool_growth = 0;
    d->rrd_snap_pool_tte_secs = 0;

    rrd_init(cfg_resolve_path("paths.rrd_file", "db/dhcp_stats.rrd"));
    return 0;
}

void detector_feed(detector_t *d, const uint8_t mac[6])
{
    sw_feed(&d->sw, mac);
    d->cur_sec_discovers++;
}

void detector_pool_update(detector_t *d, uint32_t used, uint32_t total)
{
    uint32_t now = (uint32_t)time(NULL);

    if (total == 0)
        return;
    if (used > total)
        used = total;

    d->pool_used = used;
    d->pool_total = total;
    d->pool_usage = (float)used / (float)total;

    detector_pool_sample_t *dst = &d->pool_samples[d->pool_sample_next];
    dst->ts = now;
    dst->used = used;
    dst->total = total;

    d->pool_sample_next = (d->pool_sample_next + 1) %
                          DETECTOR_POOL_HISTORY_SAMPLES;
    if (d->pool_sample_count < DETECTOR_POOL_HISTORY_SAMPLES)
        d->pool_sample_count++;

    const detector_pool_sample_t *oldest = NULL;
    for (uint32_t i = 0; i < d->pool_sample_count; i++) {
        const detector_pool_sample_t *s = &d->pool_samples[i];

        if (s->ts == 0 || s->total != total || s->ts > now)
            continue;
        if (now - s->ts > cfg_get_u32("detector.pool_history_secs", 60u))
            continue;
        if (!oldest || s->ts < oldest->ts)
            oldest = s;
    }

    d->pool_growth = 0;
    d->pool_growth_per_sec = 0.0f;
    d->pool_tte_secs = 0;

    if (oldest && now > oldest->ts) {
        uint32_t elapsed = now - oldest->ts;

        if (used > oldest->used)
            d->pool_growth = used - oldest->used;

        if (d->pool_growth > 0)
            d->pool_growth_per_sec = (float)d->pool_growth / (float)elapsed;
    }

    if (used >= total) {
        d->pool_tte_secs = 0;
    } else if (d->pool_growth_per_sec > 0.0f) {
        d->pool_tte_secs =
            (uint32_t)(((float)(total - used) / d->pool_growth_per_sec) + 0.5f);
    }
}

/*
 * Called every second (SIGALRM).
 * Does not call system(), so it is safe from a signal handler.
 */
void detector_tick(detector_t *d)
{
    /* Advance the time window. */
    sw_tick(&d->sw);

    /* Feature 3: Leaky Bucket (instantaneous rate: DISCOVERs in the last second). */
    uint32_t last_sec = d->cur_sec_discovers;
    d->cur_sec_discovers = 0;
    int f3 = lb_check(&d->lb, last_sec);

    /* Feature 4: adaptive Z-score on the 60s window rate.
     * Called every second regardless of last_sec: window_rate changes gradually
     * so the warmup accumulates correctly during quiet baseline periods too. */
    uint32_t window_rate = sw_total_discovers(&d->sw);
    uint32_t unique_macs = sw_estimate_unique_macs(&d->sw);
    uint32_t window_secs = cfg_get_u32("detector.window_secs", 60u);
    uint32_t la_window_secs = cfg_get_u32("detector.la_window_secs", 5u);
    int f2 = (unique_macs >= cfg_get_u32("detector.unique_mac_threshold", 40u) &&
              window_rate >= cfg_get_u32("detector.unique_min_discovers", 40u));

    int f4 = as_check(&d->as, window_rate);

    /* Feature 5: LA-bit ratio. */
    uint32_t la_samples = 0;
    float la = sw_recent_la_ratio(&d->sw,
                                  (int)la_window_secs,
                                  &la_samples);
    int f5 = (la_samples >= cfg_get_u32("detector.la_min_discovers", 3u) &&
              la > cfg_get_float("detector.la_threshold", 0.80f));

    uint32_t pool_min_growth = cfg_get_u32("detector.pool_min_growth", 10u);
    uint32_t pool_slow_min_growth =
        cfg_get_u32("detector.pool_slow_min_growth", pool_min_growth);

    int f6_raw = 0;
    if (d->pool_total > 0 && d->pool_growth_per_sec > 0.0f) {
        if (d->pool_growth >= pool_min_growth &&
            d->pool_usage >= cfg_get_float("detector.pool_pressure_usage", 0.70f)) {
            f6_raw = 1;
        } else if (d->pool_growth >= pool_min_growth &&
                   d->pool_usage >= cfg_get_float("detector.pool_projected_usage", 0.10f) &&
                   d->pool_tte_secs <= cfg_get_u32("detector.pool_tte_secs", 300u)) {
            f6_raw = 1;
        } else if (d->pool_growth >= pool_slow_min_growth &&
                   d->pool_usage >= cfg_get_float("detector.pool_slow_usage", 0.20f) &&
                   d->pool_tte_secs <= cfg_get_u32("detector.pool_slow_tte_secs", 900u) &&
                   unique_macs >= cfg_get_u32("detector.pool_slow_unique_macs", 10u) &&
                   window_rate >= cfg_get_u32("detector.pool_slow_discovers", 10u)) {
            f6_raw = 1;
        }
    }

    if (f6_raw)
        d->pool_alert_hold = detector_pool_alert_hold_secs();
    else if (d->pool_alert_hold > 0)
        d->pool_alert_hold--;

    int f6 = f6_raw || d->pool_alert_hold > 0;

    int score = f2 + f3 + f4 + f5 + f6;
    int attack = score >= (int)detector_score_threshold() || f6;

    if (attack)
        d->alert_hold = detector_alert_hold_secs();
    else if (d->alert_hold > 0)
        d->alert_hold--;

    d->last_attack = attack || d->alert_hold > 0;

    if (d->pool_total > 0) {
        printf("[detector] discover/sec=%-4u  discover/%us=%-5u  new-macs/%us=%-4u"
               "  la/%us=%.2f  bucket=%.0f/%.0f  baseline=%.1f+-%.1f"
               "  pool=%u/%u %.0f%% growth=%u tte=%us"
               "  f2=%d f3=%d f4=%d f5=%d f6=%d  score=%d/5%s\n",
               last_sec,
               window_secs,
               window_rate,
               window_secs,
               unique_macs,
               la_window_secs,
               la,
               lb_level(&d->lb), d->lb.capacity,
               as_ema(&d->as), as_dev(&d->as),
               d->pool_used, d->pool_total, d->pool_usage * 100.0f,
               d->pool_growth, d->pool_tte_secs,
               f2, f3, f4, f5, f6,
               score,
               d->last_attack ? "  *** ATTACK ***" : "");
    } else {
        printf("[detector] discover/sec=%-4u  discover/%us=%-5u  new-macs/%us=%-4u"
               "  la/%us=%.2f  bucket=%.0f/%.0f  baseline=%.1f+-%.1f"
               "  pool=off"
               "  f2=%d f3=%d f4=%d f5=%d f6=%d  score=%d/5%s\n",
               last_sec,
               window_secs,
               window_rate,
               window_secs,
               unique_macs,
               la_window_secs,
               la,
               lb_level(&d->lb), d->lb.capacity,
               as_ema(&d->as), as_dev(&d->as),
               f2, f3, f4, f5, f6,
               score,
               d->last_attack ? "  *** ATTACK ***" : "");
    }

    /* RRD snapshot every configured step. */
    if (++d->rrd_tick >= detector_rrd_step_secs()) {
        d->rrd_tick                 = 0;
        d->rrd_snap_discovers       = window_rate;
        d->rrd_snap_unique_macs     = unique_macs;
        d->rrd_snap_la_ratio        = sw_la_ratio(&d->sw);
        d->rrd_snap_bucket_tokens   = lb_level(&d->lb);
        d->rrd_snap_bucket_capacity = d->lb.capacity;
        d->rrd_snap_baseline_ema    = as_ema(&d->as);
        d->rrd_snap_baseline_dev    = as_dev(&d->as);
        d->rrd_snap_pool_used       = d->pool_used;
        d->rrd_snap_pool_total      = d->pool_total;
        d->rrd_snap_pool_usage_pct  = d->pool_usage * 100.0f;
        d->rrd_snap_pool_growth     = d->pool_growth;
        d->rrd_snap_pool_tte_secs   = d->pool_tte_secs;
        d->rrd_due                  = 1;
    }
}

int detector_rrd_pending(const detector_t *d)
{
    return d->rrd_due;
}

void detector_rrd_flush(detector_t *d)
{
    rrd_sample_t sample;

    sample.discovers       = (uint32_t)d->rrd_snap_discovers;
    sample.unique_macs     = (uint32_t)d->rrd_snap_unique_macs;
    sample.la_ratio        = d->rrd_snap_la_ratio;
    sample.bucket_tokens   = d->rrd_snap_bucket_tokens;
    sample.bucket_capacity = d->rrd_snap_bucket_capacity;
    sample.baseline_ema    = d->rrd_snap_baseline_ema;
    sample.baseline_dev    = d->rrd_snap_baseline_dev;
    sample.pool_used       = (uint32_t)d->rrd_snap_pool_used;
    sample.pool_total      = (uint32_t)d->rrd_snap_pool_total;
    sample.pool_usage_pct  = d->rrd_snap_pool_usage_pct;
    sample.pool_growth     = (uint32_t)d->rrd_snap_pool_growth;
    sample.pool_tte_secs   = (uint32_t)d->rrd_snap_pool_tte_secs;

    rrd_update(cfg_resolve_path("paths.rrd_file", "db/dhcp_stats.rrd"), &sample);
    d->rrd_due = 0;
}

int detector_attack_active(const detector_t *d)
{
    return d->last_attack;
}
