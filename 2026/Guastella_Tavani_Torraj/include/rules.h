#ifndef RULES_H
#define RULES_H

#include <stdint.h>
#include "packet.h"

// COSTANTI

#define RULE_ALLOW 1
#define RULE_DROP  2

#define MAX_RULES 100

#define RULES_OK     0
#define RULES_ERROR -1

// STRUTTURA REGOLA

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int action;
} rule_t;

// RISULTATO MATCH

typedef struct {
    int matched;
    int action;
} rule_result_t;

// API

int rules_init(const char *config_file);

rule_result_t check_rules(packet_t *pkt);

const char *rule_action_to_string(int action);

#endif