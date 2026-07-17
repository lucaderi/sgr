#include "netconf_worker.h"

#include <pthread.h>
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * Internal state
 * ========================================================================= */

typedef struct {
    nw_job_t        buf[NW_JOB_QUEUE_LEN];
    int             head, tail, count;
    pthread_mutex_t mtx;
    pthread_cond_t  cond;
} job_queue_t;

typedef struct {
    nw_result_t     buf[NW_RES_QUEUE_LEN];
    int             head, tail, count;
    pthread_mutex_t mtx;
} res_queue_t;

static job_queue_t    jq;
static res_queue_t    rq;
static netconf_cfg_t  wcfg;
static pthread_t      wtid;
static volatile int   wrunning = 0;

/* ---- Queue helpers ------------------------------------------------------ */

static void jq_push_locked(const nw_job_t *job)
{
    jq.buf[jq.tail] = *job;
    jq.tail = (jq.tail + 1) % NW_JOB_QUEUE_LEN;
    jq.count++;
}

static void jq_push_front_locked(const nw_job_t *job)
{
    jq.head = (jq.head + NW_JOB_QUEUE_LEN - 1) % NW_JOB_QUEUE_LEN;
    jq.buf[jq.head] = *job;
    jq.count++;
}

static int is_priority_job(nw_job_type_t type)
{
    return type == NW_JOB_ENFORCE_WL ||
           type == NW_JOB_DISABLE_WL ||
           type == NW_JOB_RESET_POOL;
}

static int jq_make_room_for_priority_locked(void)
{
    int last;

    if (jq.count < NW_JOB_QUEUE_LEN)
        return 0;

    last = (jq.tail + NW_JOB_QUEUE_LEN - 1) % NW_JOB_QUEUE_LEN;
    if (!is_priority_job(jq.buf[last].type)) {
        jq.tail = last;
        jq.count--;
        fprintf(stderr,
                "[WARN] [netconf_worker] dropped queued non-critical job "
                "for priority NETCONF action\n");
        return 0;
    }

    if (!is_priority_job(jq.buf[jq.head].type)) {
        jq.head = (jq.head + 1) % NW_JOB_QUEUE_LEN;
        jq.count--;
        fprintf(stderr,
                "[WARN] [netconf_worker] dropped queued non-critical job "
                "for priority NETCONF action\n");
        return 0;
    }

    return -1;
}

static void rq_push(const nw_result_t *res)
{
    pthread_mutex_lock(&rq.mtx);
    if (rq.count < NW_RES_QUEUE_LEN) {
        rq.buf[rq.tail] = *res;
        rq.tail = (rq.tail + 1) % NW_RES_QUEUE_LEN;
        rq.count++;
    } else {
        fprintf(stderr, "[WARN] [netconf_worker] result queue full, dropping\n");
    }
    pthread_mutex_unlock(&rq.mtx);
}

/* ---- Job handlers (run inside the worker thread) ----------------------- */

static void handle_pool_stats(void)
{
    dhcp_pool_stats_t stats;
    nw_result_t res;

    if (netconf_get_pool_stats(&wcfg, &stats) == 0) {
        res.type       = NW_RES_POOL_OK;
        res.pool.used  = stats.used;
        res.pool.total = stats.total;
    } else {
        res.type = NW_RES_POOL_FAIL;
    }
    rq_push(&res);
}

static void handle_enforce_wl(const whitelist_t *wl)
{
    nw_result_t res;

    if (netconf_enforce_whitelist(&wcfg, wl) != 0) {
        res.type = NW_RES_ENFORCE_WL_FAIL;
        rq_push(&res);
        return;
    }

    res.type = NW_RES_ENFORCE_WL_OK;
    rq_push(&res);
}

static void handle_disable_wl(void)
{
    nw_result_t res;

    if (netconf_disable_whitelist(&wcfg) != 0) {
        res.type = NW_RES_DISABLE_WL_FAIL;
        rq_push(&res);
        return;
    }

    res.type = NW_RES_DISABLE_WL_OK;
    rq_push(&res);
}

static void handle_lookup_lease(const uint8_t mac[MAC_LEN])
{
    uint32_t ip = 0;
    nw_result_t res;
    int rc;

    rc = netconf_lookup_lease(&wcfg, mac, &ip);
    if (rc == 0 && ip != 0) {
        res.type = NW_RES_LEASE_FOUND;
        memcpy(res.lease.mac, mac, MAC_LEN);
        res.lease.ip = ip;
    } else if (rc == 1) {
        res.type = NW_RES_LEASE_NOT_FOUND;
        memcpy(res.mac, mac, MAC_LEN);
    } else {
        res.type = NW_RES_LEASE_ERROR;
        memcpy(res.mac, mac, MAC_LEN);
    }
    rq_push(&res);
}

static void handle_release_lease(const uint8_t mac[MAC_LEN], uint32_t ip)
{
    nw_result_t res;

    memcpy(res.lease.mac, mac, MAC_LEN);
    res.lease.ip = ip;
    res.type = (netconf_release_lease(&wcfg, mac, ip) == 0)
        ? NW_RES_RELEASE_LEASE_OK
        : NW_RES_RELEASE_LEASE_FAIL;
    rq_push(&res);
}

static void handle_reset_pool(void)
{
    nw_result_t res;

    if (netconf_reset_pool(&wcfg) != 0) {
        res.type = NW_RES_RESET_POOL_FAIL;
        rq_push(&res);
    }
}

/* ---- Worker thread ------------------------------------------------------ */

static void *worker_thread(void *arg)
{
    (void)arg;

    for (;;) {
        nw_job_t job;

        pthread_mutex_lock(&jq.mtx);
        while (jq.count == 0 && wrunning) {
            int rc = pthread_cond_wait(&jq.cond, &jq.mtx);
            if (rc != 0) {
                fprintf(stderr,
                        "[FAIL] [netconf_worker] pthread_cond_wait failed: %d\n",
                        rc);
                wrunning = 0;
                break;
            }
        }

        if (!wrunning && jq.count == 0) {
            pthread_mutex_unlock(&jq.mtx);
            break;
        }

        job = jq.buf[jq.head];
        jq.head = (jq.head + 1) % NW_JOB_QUEUE_LEN;
        jq.count--;
        pthread_mutex_unlock(&jq.mtx);

        switch (job.type) {
            case NW_JOB_POOL_STATS:    handle_pool_stats();                        break;
            case NW_JOB_ENFORCE_WL:    handle_enforce_wl(&job.wl);                 break;
            case NW_JOB_DISABLE_WL:    handle_disable_wl();                        break;
            case NW_JOB_LOOKUP_LEASE:  handle_lookup_lease(job.mac);               break;
            case NW_JOB_RELEASE_LEASE: handle_release_lease(job.release.mac,
                                                             job.release.ip);      break;
            case NW_JOB_RESET_POOL:    handle_reset_pool();                        break;
        }
    }

    return NULL;
}

/* ---- Public API --------------------------------------------------------- */

int nw_start(const netconf_cfg_t *cfg)
{
    int rc;

    if (!cfg) {
        fprintf(stderr, "[FAIL] [netconf_worker] missing NETCONF config\n");
        return -1;
    }

    memset(&jq, 0, sizeof(jq));
    memset(&rq, 0, sizeof(rq));
    rc = pthread_mutex_init(&jq.mtx, NULL);
    if (rc != 0) {
        fprintf(stderr, "[FAIL] [netconf_worker] pthread_mutex_init jq failed: %d\n", rc);
        return -1;
    }
    rc = pthread_cond_init(&jq.cond, NULL);
    if (rc != 0) {
        fprintf(stderr, "[FAIL] [netconf_worker] pthread_cond_init failed: %d\n", rc);
        pthread_mutex_destroy(&jq.mtx);
        return -1;
    }
    rc = pthread_mutex_init(&rq.mtx, NULL);
    if (rc != 0) {
        fprintf(stderr, "[FAIL] [netconf_worker] pthread_mutex_init rq failed: %d\n", rc);
        pthread_cond_destroy(&jq.cond);
        pthread_mutex_destroy(&jq.mtx);
        return -1;
    }

    wcfg     = *cfg;
    wrunning = 1;

    rc = pthread_create(&wtid, NULL, worker_thread, NULL);
    if (rc != 0) {
        fprintf(stderr, "[FAIL] [netconf_worker] pthread_create failed: %d\n", rc);
        wrunning = 0;
        pthread_mutex_destroy(&rq.mtx);
        pthread_cond_destroy(&jq.cond);
        pthread_mutex_destroy(&jq.mtx);
        return -1;
    }
    return 0;
}

void nw_stop(void)
{
    int rc;

    pthread_mutex_lock(&jq.mtx);
    wrunning = 0;
    pthread_cond_signal(&jq.cond);
    pthread_mutex_unlock(&jq.mtx);

    rc = pthread_join(wtid, NULL);
    if (rc != 0)
        fprintf(stderr, "[WARN] [netconf_worker] pthread_join failed: %d\n", rc);

    pthread_mutex_destroy(&jq.mtx);
    pthread_cond_destroy(&jq.cond);
    pthread_mutex_destroy(&rq.mtx);
}

int nw_enqueue(const nw_job_t *job)
{
    if (!job) {
        fprintf(stderr, "[FAIL] [netconf_worker] enqueue called with NULL job\n");
        return -1;
    }

    pthread_mutex_lock(&jq.mtx);
    if (jq.count >= NW_JOB_QUEUE_LEN) {
        if (!is_priority_job(job->type) ||
            jq_make_room_for_priority_locked() != 0) {
            pthread_mutex_unlock(&jq.mtx);
            fprintf(stderr, "[WARN] [netconf_worker] job queue full, dropping type=%d\n",
                    (int)job->type);
            return -1;
        }
    }
    if (is_priority_job(job->type))
        jq_push_front_locked(job);
    else
        jq_push_locked(job);
    pthread_cond_signal(&jq.cond);
    pthread_mutex_unlock(&jq.mtx);
    return 0;
}

int nw_dequeue_result(nw_result_t *out)
{
    if (!out) {
        fprintf(stderr, "[FAIL] [netconf_worker] dequeue called with NULL output\n");
        return -1;
    }

    pthread_mutex_lock(&rq.mtx);
    if (rq.count == 0) {
        pthread_mutex_unlock(&rq.mtx);
        return -1;
    }
    *out = rq.buf[rq.head];
    rq.head = (rq.head + 1) % NW_RES_QUEUE_LEN;
    rq.count--;
    pthread_mutex_unlock(&rq.mtx);
    return 0;
}
