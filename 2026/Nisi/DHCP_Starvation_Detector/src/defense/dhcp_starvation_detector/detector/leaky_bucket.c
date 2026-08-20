#include "leaky_bucket.h"

void lb_init(leaky_bucket_t *lb, double capacity, double refill_per_sec)
{
    lb->capacity       = capacity;
    lb->refill_per_sec = refill_per_sec;
    lb->bucket         = capacity;   /* starts full: no attack in progress */
}

/*
 * Sequence every second:
 *  1. Refill: add refill_per_sec credits (not above capacity).
 *  2. Drain: subtract new_events credits.
 *  3. If bucket <= 0 -> the rate exceeded the threshold -> alert.
 *
 * The bucket is clamped to 0 (it does not go negative), so the next-second
 * refill starts from 0 and not from a negative value; otherwise a very large
 * burst would take many seconds to "recover" credits even after the attack ends.
 */
int lb_check(leaky_bucket_t *lb, uint32_t new_events)
{
    lb->bucket += lb->refill_per_sec;
    if (lb->bucket > lb->capacity)
        lb->bucket = lb->capacity;

    lb->bucket -= (double)new_events;

    if (lb->bucket <= 0.0) {
        lb->bucket = 0.0;
        return 1;
    }
    return 0;
}

double lb_level(const leaky_bucket_t *lb)
{
    return lb->bucket;
}
