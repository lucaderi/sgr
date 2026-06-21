#ifndef MAC_REPUTATION_H
#define MAC_REPUTATION_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "../whitelist/whitelist.h"

/* ---- Fallback thresholds and static caps ---------------------------------
 * Runtime values are read from config/config.yaml by mac_reputation.c. These
 * constants remain as safe defaults and array bounds for the C structs.
 */
#define MR_MIN_DISCOVERS   4    /* minimum DISCOVERs to consider a MAC legitimate */
#define MR_MAX_DISCOVERS   8    /* above this, likely a buggy loop or slow attack */
#define MR_MIN_INTERVAL_S  4    /* minimum interval between consecutive DISCOVERs */
#define MR_MAX_INTERVAL_S  90   /* maximum interval                               */
#define MR_OBS_WINDOW_S    300  /* forget a MAC after 5 minutes of silence        */
#define MR_PRESSURE_MIN_DISCOVERS 5  /* require more evidence if pipeline is full */
#define MR_PRESSURE_MIN_AGE_S 30     /* minimum observation time under pressure   */
#define MR_BACKOFF_MIN_SPAN_S 20     /* minimum total retry span for promotion    */
#define MR_BACKOFF_GROWTH_PERCENT 175 /* max gap must be >= min gap * this percent */
#define MR_BACKOFF_MIN_GROWTH_STEPS 1 /* required increasing retry transitions     */

/* ---- ARP probe ---------------------------------------------------------- */
#define MR_ARP_RETRIES     3    /* ARP attempts before rejecting                  */
#define MR_ARP_RETRY_S     5    /* seconds between attempts                       */
#define MR_LEASE_HINT_ARP_DELAY_S 8 /* delay before ARP if ACK was not visible      */

/* ---- Table sizes -------------------------------------------------------- */
#define MR_MAX_ENTRIES     1024 /* concurrently tracked MACs (LRU)               */
#define MR_CANDIDATES      256  /* first sightings before the real table         */
#define MR_MAX_TRACKING    256  /* quota for MACs not yet credible               */
#define MR_MAX_READY       32   /* quota for credible MACs not yet whitelisted   */
#define MR_MAX_TEMP_WL     2    /* unconfirmed temporary whitelist quota         */
#define MR_PROMOTE_INTERVAL_S 20 /* one real promotion every N seconds            */
#define MR_PRESSURE_ENTRIES 96  /* stricter heuristic above this threshold       */
#define MR_GATE_SLOTS      5    /* temporal Bloom filters                        */
#define MR_GATE_SLOT_S     60   /* duration of each Bloom filter                  */
#define MR_GATE_BITS       8192 /* must be a multiple of 8                        */
#define MR_GATE_BYTES      (MR_GATE_BITS / 8)

/* ---- State timeouts ----------------------------------------------------- */
#define MR_READY_TTL_S       300  /* credible but not yet whitelisted               */
#define MR_PROVISIONAL_TTL_S 45   /* temporarily whitelisted but no ACK yet         */
#define MR_REJECTED_TTL_S    300  /* keep rejection for a short time                */
#define MR_CONFIRMED_TTL_S   3600 /* confirmation valid for 1h                      */

/* ---- MAC lifecycle states ----------------------------------------------- */
typedef enum {
    MR_TRACKING,    /* collecting DISCOVERs, heuristic not yet satisfied     */
    MR_READY,       /* heuristic OK, but NOT yet whitelisted                 */
    MR_PROVISIONAL, /* temporarily whitelisted, waiting for ACK              */
    MR_ARP_PENDING, /* received IP, ARP probes in progress                   */
    MR_CONFIRMED,   /* ARP replied -> confirmed legitimate                   */
    MR_REJECTED,    /* ARP failed -> removed from whitelist                  */
} mr_state_t;

typedef struct {
    uint8_t    mac[6];
    mr_state_t state;
    uint32_t   assigned_ip;             /* assigned IP, network byte order      */
    time_t     ts[MR_MAX_DISCOVERS];    /* timestamps of received DISCOVERs      */
    int        disc_count;
    time_t     first_seen;
    time_t     last_seen;
    time_t     state_since;
    int        arp_tries;
    time_t     arp_next;                /* when to send the next ARP             */
    pid_t      arp_pid;                 /* child arping process PID              */
} mr_entry_t;

typedef struct {
    int     used;
    uint8_t mac[6];
    time_t  first_seen;
    time_t  last_seen;
} mr_candidate_t;

typedef struct {
    time_t  epoch;
    uint8_t bits[MR_GATE_BYTES];
} mr_gate_slot_t;

/* Callbacks invoked on state transitions.
 * on_promote opens only the temporary whitelist; READY does not call callbacks.
 */
typedef void (*mr_promote_cb)(const uint8_t mac[6], void *ctx);
typedef void (*mr_confirm_cb)(const uint8_t mac[6], uint32_t ip, void *ctx);
typedef void (*mr_reject_cb) (const uint8_t mac[6], uint32_t ip, void *ctx);

typedef struct {
    mr_entry_t    table[MR_MAX_ENTRIES];
    mr_candidate_t candidates[MR_CANDIDATES];
    mr_gate_slot_t gate[MR_GATE_SLOTS];
    int           count;
    time_t        next_promotion;
    char          iface[32];
    whitelist_t   confirmed_wl;
    int           confirmed_wl_enabled;
    mr_promote_cb on_promote;
    mr_confirm_cb on_confirm;
    mr_reject_cb  on_reject;
    void         *cb_ctx;
} mac_reputation_t;

/*
 * Initialize the module.
 * iface: interface used for ARP probes (for example "ens160")
 * Callbacks can be NULL.
 */
void mr_init(mac_reputation_t *mr,
             const char       *iface,
             mr_promote_cb     on_promote,
             mr_confirm_cb     on_confirm,
             mr_reject_cb      on_reject,
             void             *ctx);

/* Enable persistence of CONFIRMED MACs into a whitelist database file. */
int mr_enable_confirmed_whitelist(mac_reputation_t *mr, const char *path);

/* Notify a received DHCP DISCOVER. */
void mr_feed_discover(mac_reputation_t *mr, const uint8_t mac[6], time_t ts);

/* Notify a received DHCP ACK (server -> client). yiaddr = assigned IP. */
void mr_feed_ack(mac_reputation_t *mr, const uint8_t mac[6],
                 uint32_t yiaddr, time_t ts);

/*
 * Notify a visible lease hint while the MAC is temporarily whitelisted.
 * This is useful on a separate monitor host because DHCP ACK may be unicast
 * to the client and therefore invisible, while OFFER/REQUEST are often
 * broadcast. ARP confirmation is still required before final promotion.
 */
void mr_feed_lease_hint(mac_reputation_t *mr, const uint8_t mac[6],
                        uint32_t ip, time_t ts, const char *source);

/*
 * Module tick: call every second from the main loop.
 * Handles asynchronous ARP probes and eviction of expired entries.
 */
void mr_tick(mac_reputation_t *mr, time_t now);

const char *mr_state_str(mr_state_t s);

#endif /* MAC_REPUTATION_H */
