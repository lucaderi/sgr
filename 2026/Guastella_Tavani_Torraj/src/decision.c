#include <stdio.h>
#include <time.h>

#include "decision.h"

static int default_policy = DECISION_DROP;
static FILE *log_file = NULL;

// INIT

void decision_init(void)
{
    default_policy = DECISION_DROP;

    log_file = fopen("firewall.log", "a");

    if (!log_file) {
        perror("fopen failed");
    }

    // Init rate limiter
    if (rate_limit_init() != 0) {
        fprintf(stderr,"Rate limit init failed\n");
    }

    // Init HyperLogLog
    if (hll_init() != 0) {
        fprintf(stderr,"HLL init failed\n");
    }
}

// CLEANUP

void decision_cleanup(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

// LOG PACCHETTO

static void log_packet(packet_t *pkt, const char *reason, int decision){
    
    if (!log_file || !pkt) return;

    time_t now = time(NULL);

    struct tm *t = localtime(&now);

    if (!t) return;

    fprintf(
        log_file,
        "[%02d:%02d:%02d] "
        "SRC=%s DST=%s "
        "SPORT=%d DPORT=%d "
        "PROTO=%d "
        "DECISION=%s "
        "REASON=%s\n",

        t->tm_hour,
        t->tm_min,
        t->tm_sec,

        pkt->src_ip,
        pkt->dst_ip,

        pkt->src_port,
        pkt->dst_port,

        pkt->protocol,

        decision == DECISION_ACCEPT
            ? "ACCEPT"
            : "DROP",

        reason
    );

    fflush(log_file);
}

// LOG STATS

static void log_stats(void){
    
    if (!log_file) return;

    int unique_ips = hll_get_cardinality();

    fprintf(log_file, "[STATS] Unique source IPs ≈ %d\n", unique_ips);

    fflush(log_file);
}

// DECISION ENGINE

decision_result_t decide(packet_t *pkt){
    
    if (pkt == NULL) {

        return (decision_result_t){
            DECISION_DROP,
            "NULL_PACKET"
        };
    }

    // HLL

    if (hll_add_ip(pkt->src_ip) != 0) {

        if (log_file) {

            fprintf(log_file, "[WARN] HLL_ERROR: %s\n", hll_last_error());

            fflush(log_file);
        }
    }

    // RULES

    rule_result_t rr = check_rules(pkt);

    int base_decision = default_policy;

    const char *reason = "DEFAULT_POLICY";

    if (rr.matched) {

        // DROP immediato
        if (rr.action == RULE_DROP) {

            log_packet(pkt, "RULE_DROP", DECISION_DROP);

            return (decision_result_t){
                DECISION_DROP,
                "RULE_DROP"
            };
        }

        // ALLOW + rate limit
        if (rr.action == RULE_ALLOW) {

            base_decision = DECISION_ACCEPT;

            reason = "RULE_ALLOW";
        }
    }

    // RATE LIMIT

    int rl = rate_limit_check(pkt);

    if (rl == RATE_LIMIT_DROP) {

        log_packet(pkt, "RATE_LIMIT", DECISION_DROP);

        return (decision_result_t){
            DECISION_DROP,
            "RATE_LIMIT"
        };
    }

    if (rl == RATE_LIMIT_ERROR) {

        log_packet(pkt, "RATE_LIMIT_ERROR", DECISION_DROP);

        return (decision_result_t){
            DECISION_DROP,
            "RATE_LIMIT_ERROR"
        };
    }

    // Decisione

    log_packet(pkt, reason, base_decision);

    static int counter = 0;

    counter++;

    if (counter % 50 == 0) {
        log_stats();
    }

    return (decision_result_t){

        .decision = base_decision,
        .reason = reason
    };
}