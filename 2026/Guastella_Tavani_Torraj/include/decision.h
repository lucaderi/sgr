#ifndef DECISION_H
#define DECISION_H

#include "rules.h"
#include "rate_limit.h"
#include "hyperloglog.h"

// COSTANTI

#define DECISION_ACCEPT 1
#define DECISION_DROP   0

// RISULTATO

typedef struct {
    int decision;
    const char *reason;
} decision_result_t;

// API

void decision_init(void);
void decision_cleanup(void);
decision_result_t decide(packet_t *pkt);

#endif