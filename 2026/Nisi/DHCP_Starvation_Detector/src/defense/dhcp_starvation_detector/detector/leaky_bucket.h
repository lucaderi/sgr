#ifndef LEAKY_BUCKET_H
#define LEAKY_BUCKET_H

#include <stdint.h>

/*
 * leaky_bucket - Feature 3 of the detection engine.
 *
 * Fast absolute threshold: fires when the DISCOVER rate exceeds a fixed limit,
 * regardless of past history.
 *
 * Behavior (Deri, tm2026.pdf slides 272-273):
 *   The bucket represents "available credits".
 *   - Every second it refills by refill_per_sec credits (up to capacity).
 *   - Every DISCOVER consumes 1 credit.
 *   - If credits reach 0 -> alert.
 *
 * Typical usage:
 *   lb_init(&lb, capacity, refill_per_sec);
 *   // every second, after sw_tick():
 *   if (lb_check(&lb, sw_total_discovers(&sw))) { ... }
 */

typedef struct {
    double capacity;        /* maximum bucket size (burst tolerance) */
    double refill_per_sec;  /* credits added every second (expected normal rate) */
    double bucket;          /* remaining credits */
} leaky_bucket_t;

/*
 * Initialize the bucket as full ("no attack in progress" state).
 * capacity       - maximum burst tolerated in one second
 * refill_per_sec - expected normal rate (credits/sec)
 */
void lb_init(leaky_bucket_t *lb, double capacity, double refill_per_sec);

/*
 * Call every second with the number of DISCOVERs received in the last second
 * (typically the current slot, not the whole window).
 * Returns 1 if the bucket is exhausted (anomaly), 0 otherwise.
 */
int lb_check(leaky_bucket_t *lb, uint32_t new_events);

/* Current credits in the bucket [0 .. capacity]. */
double lb_level(const leaky_bucket_t *lb);

#endif /* LEAKY_BUCKET_H */
