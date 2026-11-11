#include <getopt.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ingester.h"
#include "discretizer.h"
#include "common.h"
#include "rrd_reporter.h"

static void print_usage() {
    printf("Usage: [OPTIONS]\n");
    printf("\nOptions:\n");
    printf("  -r FILE                  Read packets from pcap file (required)\n");
    printf("  -l IP                    Inbound IP address for pcap file (required)\n");
    printf("  -o PATH                  RRD database path (default: test/out/netflow_metrics.rrd)\n");
    printf("  -t VAL                   Anomaly probability threshold (default: 0.01)\n");
    printf("  -c VAL                   Markov Matrix convergence threshold (default: 0.001)\n");
    printf("  -n NUM                   Norm check interval packets (default: 1000)\n");
    printf("  -m NUM                   Maximum concurrent flows (default: 100000)\n");
    printf("  -h                       Show this help\n");
    printf("\nExample:\n");
    printf("    -r capture.pcap -l 192.168.1.100 -t 0.005 -n 500\n");
}

int main(int argc, char *argv[]) {
        Config config;
        init_config(&config);
    if (argc < 2) {
        print_usage();
        return -1;
    }
    else {
        int opt;
        while ((opt = getopt(argc, argv, "r:l:o:t:c:n:m:h")) != -1) {
            switch (opt) {
                case 'r':
                    config.pcap_file = strdup(optarg);
                    break;
                case 'l':
                    if (inet_pton(AF_INET, optarg, &config.local_ip) <= 0) {
                        fprintf(stderr, "Errore: Indirizzo IP non valido '%s'\n", optarg);
                        free_config(&config);
                        print_usage();
                        return -1;
                    }
                    break;
                case 'o':
                    config.rrd_path = strdup(optarg);
                    break;
                case 't':
                    config.threshold = atof(optarg);
                    break;
                case 'c':
                    config.convergence = atof(optarg);
                    break;
                case 'n':
                    config.norm_interval_check = atoi(optarg);
                    break;
                case 'm':
                    config.max_flows = atoi(optarg);
                    break;
                case 'h':
                    print_usage();
                    return 0;
                default:
                    print_usage();
                    return -1;
            }
        }

        if (config.pcap_file == NULL) {
            fprintf(stderr, "Error: Must specify -r (pcap file)\n");
            print_usage();
            free_config(&config);
            return -1;
        }
        if (config.local_ip == 0) {
            fprintf(stderr, "Error: Must specify -l (local IP)\n");
            print_usage();
            free_config(&config);
            return -1;
        }
    }

    config.norm_interval_check = config.norm_interval_check; // Configured via CLI or default
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(config.pcap_file, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

        CaptureContext ctx;
        ctx.training_done = false;
        ctx.total_packets = 0;
        ctx.monitored_packets = 0;
        ctx.total_anomalies = 0;
        ctx.pcap_start_time = 0;
        ctx.pcap_end_time = 0;
        ctx.handle = handle;
        ctx.config = &config;

        if (init_ndpi_engine(&ctx) != 0) {
            fprintf(stderr, "Error: Failed to initialize NDPI engine\n");
            free_config(&config);
            return 1;
        }

        if (pcap_loop(handle, -1, offline_packet_callback, (u_char *)&ctx) < 0) {
            fprintf(stderr, "Warning: pcap_loop exited with error\n");
        }

        // Genera automaticamente i grafici RRD alla fine dell'elaborazione offline
        if (config.rrd_path != NULL) {
            generate_rrd_graphs(config.rrd_path, ctx.pcap_start_time, ctx.pcap_end_time);
        }

        // Post-processing: iterate over all identified flows and print their Markov transition probability matrices
        printf("\n=== Per-Flow Markov Transition Probability Matrices ===\n\n");
        flow_table_t *current_flow, *tmp;
        flow_table_t *head = get_flow_table_head();

        HASH_ITER(hh, head, current_flow, tmp) {
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current_flow->key.local_ip, src_ip_str, sizeof(src_ip_str));
            inet_ntop(AF_INET, &current_flow->key.remote_ip, dst_ip_str, sizeof(dst_ip_str));

            printf("Flow: %s:%u -> %s:%u (Proto: %u, Packets: %u)\n",
                   src_ip_str, ntohs(current_flow->key.local_port),
                   dst_ip_str, ntohs(current_flow->key.remote_port),
                   current_flow->key.layer4_protocol,
                   current_flow->packet_count);

            double prob_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
            normalize_markov_matrix(current_flow->markov.transition_matrix, prob_matrix);

            // Print state labels
            printf("   ");
            for (int j = 0; j < MARKOV_STATE_SPACE; j++) {
                printf("%5d ", j);
            }
            printf("\n");

            // Print probability matrix
            for (int i = 0; i < MARKOV_STATE_SPACE; i++) {
                printf("  %2d|", i);
                for (int j = 0; j < MARKOV_STATE_SPACE; j++) {
                    if (prob_matrix[i][j] > 0.0) {
                        printf("%5.3f ", prob_matrix[i][j]);
                    } else {
                        printf("    - ");
                    }
                }
                printf("\n");
            }
            printf("\n--------------------------------------------------\n\n");
        }

        cleanup_flows();
        cleanup_context(&ctx);
        free_config(&config);
        return 0;
    }

