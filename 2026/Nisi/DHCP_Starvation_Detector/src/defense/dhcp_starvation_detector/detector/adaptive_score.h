#ifndef ADAPTIVE_SCORE_H
#define ADAPTIVE_SCORE_H

#include <stdint.h>

/*
 * adaptive_score - Feature 4 of the detection engine.
 *
 * Adaptive threshold based on a Z-score with an EMA baseline: learns what is
 * "normal" for the network and fires when the current rate deviates
 * significantly. Works well on networks with variable DHCP traffic (morning
 * peak, quiet nights).
 *
 * Algorithm (Deri, tm2026.pdf):
 *
 *   Every second, given current rate r and state (ema, dev):
 *
 *   1. PREDICT with the previous state:
 *        prediction = ema                          [slide 221-223]
 *
 *   2. ANOMALY if:
 *        r > ema + delta * dev                     [slide 231-234]
 *      (no alerts during warmup)
 *
 *   3. UPDATE EMA (Single Exponential Smoothing):
 *        ema_new = alpha * r + (1-alpha) * ema     [slide 221-223]
 *
 *   4. UPDATE DEVIATION (Brutlag/Holt-Winters method):
 *        dev_new = gamma * |r - prediction| + (1-gamma) * dev   [slide 231-234]
 *
 * Parameters are read by detector_init() from config/config.yaml.
 */

typedef struct {
    double   alpha;     /* EMA smoothing factor [0 < alpha < 1] */
    double   gamma;     /* deviation smoothing factor [0 < gamma < 1] */
    double   delta;     /* threshold multiplier (number of deviations) */
    double   ema;       /* exponential moving average of the rate (discovers/sec) */
    double   dev;       /* deviation estimate (Brutlag method) */
    uint32_t samples;   /* samples seen so far */
    uint32_t warmup;    /* samples required before alerts are enabled */
} adaptive_score_t;

/*
 * Initialize the structure.
 * The alpha, gamma, delta, and warmup parameters are configurable.
 */
void as_init(adaptive_score_t *as,
             double alpha, double gamma, double delta,
             uint32_t warmup);

/*
 * Update state with the current rate and check for an anomaly.
 * Call every second with sw_total_discovers() as argument.
 * Returns 1 if the rate is anomalous, 0 otherwise.
 * During warmup it always returns 0.
 */
int as_check(adaptive_score_t *as, uint32_t rate);

/* Current EMA and deviation values (useful for debugging and RRD graphs). */
double as_ema(const adaptive_score_t *as);
double as_dev(const adaptive_score_t *as);

#endif /* ADAPTIVE_SCORE_H */
