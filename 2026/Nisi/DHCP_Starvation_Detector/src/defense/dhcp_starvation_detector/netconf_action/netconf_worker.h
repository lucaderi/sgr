#ifndef NETCONF_WORKER_H
#define NETCONF_WORKER_H

#include <stdint.h>

#include "../whitelist/whitelist.h"
#include "netconf_action.h"

/*
 * netconf_worker — non-blocking NETCONF I/O bridge.
 *
 * All blocking NETCONF calls (up to reply_timeout_ms = 15 s each) are
 * executed in a dedicated background thread.  The main loop enqueues jobs
 * and drains results without ever blocking.
 *
 * Job queue  (main  → worker): nw_enqueue()
 * Result queue (worker → main): nw_dequeue_result()
 *
 * Queue sizes are intentionally small; if the job queue is full the job is
 * silently dropped (logged).  Callers must retry on the next cycle.
 */

#define NW_JOB_QUEUE_LEN  16
#define NW_RES_QUEUE_LEN  32

/* ---- Job types (main → worker) ----------------------------------------- */

typedef enum {
    NW_JOB_POOL_STATS,
    NW_JOB_ENFORCE_WL,
    NW_JOB_DISABLE_WL,
    NW_JOB_LOOKUP_LEASE,
    NW_JOB_RELEASE_LEASE,
    NW_JOB_RESET_POOL,
} nw_job_type_t;

typedef struct {
    nw_job_type_t type;
    union {
        whitelist_t wl;                            /* copy for ENFORCE_WL      */
        uint8_t     mac[MAC_LEN];                  /* LOOKUP_LEASE             */
        struct { uint8_t mac[MAC_LEN]; uint32_t ip; } release; /* RELEASE_LEASE */
    };
} nw_job_t;

/* ---- Result types (worker → main) -------------------------------------- */

typedef enum {
    NW_RES_POOL_OK,
    NW_RES_POOL_FAIL,
    NW_RES_ENFORCE_WL_OK,
    NW_RES_LEASE_FOUND,
    NW_RES_LEASE_NOT_FOUND,   /* MAC not yet in DHCP lease table      */
    NW_RES_LEASE_ERROR,       /* NETCONF call failed                  */
    NW_RES_ENFORCE_WL_FAIL,
    NW_RES_DISABLE_WL_OK,
    NW_RES_DISABLE_WL_FAIL,
    NW_RES_RELEASE_LEASE_OK,
    NW_RES_RELEASE_LEASE_FAIL,
    NW_RES_RESET_POOL_FAIL,
} nw_res_type_t;

typedef struct {
    nw_res_type_t type;
    union {
        struct { uint32_t used; uint32_t total; } pool;  /* POOL_OK              */
        struct { uint8_t mac[MAC_LEN]; uint32_t ip; } lease; /* LEASE/RELEASE    */
        uint8_t mac[MAC_LEN];  /* LEASE_NOT_FOUND, LEASE_ERROR                   */
    };
} nw_result_t;

/* ---- Public API --------------------------------------------------------- */

/* Start the worker thread. Must be called once before nw_enqueue(). */
int  nw_start(const netconf_cfg_t *cfg);

/* Signal the worker to stop and wait for it to exit. */
void nw_stop(void);

/* Enqueue a job. Returns 0 on success, -1 if the queue is full (job dropped). */
int  nw_enqueue(const nw_job_t *job);

/* Dequeue one result. Returns 0 if a result was available, -1 if empty. */
int  nw_dequeue_result(nw_result_t *out);

#endif /* NETCONF_WORKER_H */
