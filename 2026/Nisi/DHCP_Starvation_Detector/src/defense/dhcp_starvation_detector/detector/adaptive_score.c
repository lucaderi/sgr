#include "adaptive_score.h"

static double d_abs(double x) { return x < 0.0 ? -x : x; }

void as_init(adaptive_score_t *as,
             double alpha, double gamma, double delta,
             uint32_t warmup)
{
    as->alpha   = alpha;
    as->gamma   = gamma;
    as->delta   = delta;
    as->ema     = 0.0;
    as->dev     = 0.0;
    as->samples = 0;
    as->warmup  = warmup;
}

/*
 * Sequence every second:
 *
 *  1. First sample: initialize EMA to the real value to avoid a false initial
 *     spike (if we started from 0, any traffic would look anomalous).
 *
 *  2. Following samples:
 *     a. Save the prediction (previous EMA) before updating it.
 *     b. Check anomaly (only after warmup and only if dev is significant):
 *          r > ema + delta * dev
 *        The dev >= 1.0 guard avoids alerts in early phases where deviation is
 *        still almost zero and any noise would exceed the band.
 *     c. Update EMA (Deri, slides 221-223):
 *          ema_new = alpha * r + (1-alpha) * ema
 *     d. Update deviation with the Brutlag method (Deri, slides 231-234):
 *          dev_new = gamma * |r - prediction| + (1-gamma) * dev
 *        Uses the prediction (previous EMA), not the updated one: this is the
 *        original Brutlag formula, LISA 2000.
 */
int as_check(adaptive_score_t *as, uint32_t rate)
{
    double r = (double)rate;
    int alert = 0;

    if (as->samples == 0) {
        as->ema = r;
        as->dev = 0.0;
        as->samples++;
        return 0;
    }

    double prediction = as->ema;

    if (as->samples >= as->warmup && as->dev >= 1.0) {
        if (r > prediction + as->delta * as->dev)
            alert = 1;
    }

    /* Do not update the baseline during an anomaly: EMA must not chase the
     * attack rate and raise the threshold while the attack is in progress
     * (original Brutlag behavior, LISA 2000). */
    if (!alert) {
        as->ema = as->alpha * r + (1.0 - as->alpha) * as->ema;
        as->dev = as->gamma * d_abs(r - prediction) + (1.0 - as->gamma) * as->dev;
    }

    as->samples++;
    return alert;
}

double as_ema(const adaptive_score_t *as) { return as->ema; }
double as_dev(const adaptive_score_t *as) { return as->dev; }
