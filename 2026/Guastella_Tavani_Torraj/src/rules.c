#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "rules.h"

static rule_t rules[MAX_RULES];
static int rules_count = 0;

static int is_comment_or_blank(const char *line){

    while (isspace((unsigned char)*line)) {
        line++;
    }

    return *line == '\0' || *line == '#';
}

static int parse_action(const char *s, int *out){

    if (strcmp(s, "ALLOW") == 0) {
        *out = RULE_ALLOW;
        return RULES_OK;
    }

    if (strcmp(s, "DROP") == 0) {
        *out = RULE_DROP;
        return RULES_OK;
    }

    return RULES_ERROR;
}

static int parse_protocol(const char *s, int *out){

    if (strcmp(s, "ANY") == 0) {
        *out = -1;
        return RULES_OK;
    }

    if (strcmp(s, "TCP") == 0) {
        *out = 6;
        return RULES_OK;
    }

    if (strcmp(s, "UDP") == 0) {
        *out = 17;
        return RULES_OK;
    }

    if (strcmp(s, "ICMP") == 0) {
        *out = 1;
        return RULES_OK;
    }

    return RULES_ERROR;
}

static int parse_port(const char *s, int *out){

    char *end;
    long value;

    if (strcmp(s, "ANY") == 0) {
        *out = -1;
        return RULES_OK;
    }

    errno = 0;
    value = strtol(s, &end, 10);

    if (errno != 0 || end == s || *end != '\0' || value < 0 || value > 65535) {
        return RULES_ERROR;
    }

    *out = (int)value;
    return RULES_OK;
}

static int valid_ip_or_any(const char *s){

    struct in_addr addr;

    if (strcmp(s, "ANY") == 0) {
        return 1;
    }

    return inet_pton(AF_INET, s, &addr) == 1;
}

static int match_ip(const char *rule_ip, const char *pkt_ip){

    if (strcmp(rule_ip, "ANY") == 0)
        return 1;

    return strcmp(rule_ip, pkt_ip) == 0;
}

static int match_port(int rule_port, int pkt_port){

    if (rule_port == -1)
        return 1;

    return rule_port == pkt_port;
}

static int match_protocol(int rule_proto, int pkt_proto){

    if (rule_proto == -1)
        return 1;

    return rule_proto == pkt_proto;
}

// Cerca corrispondenza con le regole del file .conf

static int match_rule(packet_t *pkt, rule_t *r){

    if (!match_ip(r->src_ip, pkt->src_ip)) return 0;

    if (!match_ip(r->dst_ip, pkt->dst_ip)) return 0;

    if (!match_protocol(r->protocol, pkt->protocol)) return 0;

    // ICMP non usa porte
    if (pkt->protocol != 1) {

        if (!match_port(r->src_port, pkt->src_port)) return 0;

        if (!match_port(r->dst_port, pkt->dst_port)) return 0;
    }

    return 1;
}

// LOAD RULES

int rules_init(const char *config_file){

    FILE *fp;

    char line[256];

    rules_count = 0;

    fp = fopen(config_file, "r");

    if (!fp) {
        perror("fopen firewall.conf");
        return RULES_ERROR;
    }

    while (fgets(line, sizeof(line), fp)) {

        // Salta commenti e righe vuote, anche con spazi iniziali.
        if (is_comment_or_blank(line))
            continue;

        char action[16];
        char src_ip[32];
        char dst_ip[32];
        char src_port[16];
        char dst_port[16];
        char proto[16];

        int fields = sscanf(
            line,
            "%15s %31s %31s %15s %15s %15s",
            action,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto
        );

        if (fields != 6) {
            fprintf(stderr, "Regola invalida: %s", line);
            continue;
        }

        if (rules_count >= MAX_RULES) {
            fprintf(stderr, "MAX_RULES raggiunto\n");
            break;
        }

        rule_t r;
        int action_value;
        int src_port_value;
        int dst_port_value;
        int protocol_value;

        if (!valid_ip_or_any(src_ip) || !valid_ip_or_any(dst_ip)) {
            fprintf(stderr, "IP non valido nella regola: %s", line);
            continue;
        }

        if (parse_action(action, &action_value) != RULES_OK) {
            fprintf(stderr, "Azione non valida nella regola: %s", line);
            continue;
        }

        if (parse_port(src_port, &src_port_value) != RULES_OK ||
            parse_port(dst_port, &dst_port_value) != RULES_OK) {
            fprintf(stderr, "Porta non valida nella regola: %s", line);
            continue;
        }

        if (parse_protocol(proto, &protocol_value) != RULES_OK) {
            fprintf(stderr, "Protocollo non valido nella regola: %s", line);
            continue;
        }

        strncpy(r.src_ip, src_ip, sizeof(r.src_ip));
        r.src_ip[15] = '\0';

        strncpy(r.dst_ip, dst_ip, sizeof(r.dst_ip));
        r.dst_ip[15] = '\0';

        r.src_port = src_port_value;
        r.dst_port = dst_port_value;

        r.protocol = protocol_value;

        r.action = action_value;

        rules[rules_count++] = r;
    }

    fclose(fp);

    printf("[RULES] Caricate %d regole da %s\n", rules_count, config_file);

    return RULES_OK;
}

rule_result_t check_rules(packet_t *pkt){

    if (pkt == NULL) {
        return (rule_result_t){0, 0};
    }

    for (int i = 0; i < rules_count; i++) {

        if (match_rule(pkt, &rules[i])) {

            return (rule_result_t){
                .matched = 1,
                .action = rules[i].action
            };
        }
    }

    return (rule_result_t){0, 0};
}

// To String

const char *rule_action_to_string(int action)
{
    switch (action) {

        case RULE_ALLOW:
            return "ALLOW";

        case RULE_DROP:
            return "DROP";

        default:
            return "UNKNOWN";
    }
}
