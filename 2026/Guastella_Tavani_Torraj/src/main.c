#include <stdio.h>

#include "nfqueue_core.h"
#include "parser.h"
#include "decision.h"
#include "rules.h"

// CALLBACK

int handle_packet(unsigned char *data, int len){

    packet_t pkt;

    if (parse_packet(data, len, &pkt) == 0) {

        fprintf(stderr, "Errore parsing pacchetto\n");

        return 1;
    }

    printf("SRC=%s DST=%s PROTO=%d SPORT=%d DPORT=%d\n",
        pkt.src_ip,
        pkt.dst_ip,
        pkt.protocol,
        pkt.src_port,
        pkt.dst_port
    );

    decision_result_t res = decide(&pkt);

    return res.decision;
}

// MAIN

int main(int argc, char *argv[])
{
    // Carica regole da file
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    if (rules_init(argv[1]) != 0) {

        fprintf(stderr, "Errore caricamento %s\n", argv[1]);

        return 1;
    }

    // Init decision engine
    decision_init();

    // Init NFQUEUE
    if (nfqueue_init(handle_packet) < 0) {

        fprintf(stderr, "Errore init NFQUEUE\n");

        decision_cleanup();

        return 1;
    }

    nfqueue_run();

    nfqueue_cleanup();

    decision_cleanup();

    return 0;
}
