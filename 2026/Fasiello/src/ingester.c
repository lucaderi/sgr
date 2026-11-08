#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ndpi_includes.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include "rrd_reporter.h"
#include "discretizer.h"
#include "ndpi_api.h"
#include "ndpi_protocol_ids.h"
#include "ndpi_typedefs.h"
#include "uthash.h"

/**
 * Genera un flusso non normalizzato a partire dal pacchetto fornito.
 * Usato come chiave per hashmaps (UTHash?).
 *
 * @param caplen Lunghezza del pacchetto
 * @param packet Puntatore al pacchetto
 * @return flow_nn_t Flusso non normalizzato
 */
flow_nn_t create_flow(uint16_t caplen, const u_char *packet) {
    flow_nn_t flow;
    // Zero-out memory so that it plays nice with UTHash
    memset(&flow, 0, sizeof(flow_nn_t));

    // Analizzo il pacchetto fino al Layer Trasporto
    // (Analisi della lunghezza del protocollo di trasporto viene eseguita dinamicamente con ihl)
    size_t min_len = sizeof(struct ether_header) + sizeof(struct iphdr);

    // Verifico se il pacchetto è abbastanza lungo
    if (caplen < min_len) {
        fprintf(stderr, "Pacchetto troppo corto: caplen=%u, min_len=%zu\n", caplen, min_len);
        return flow;
    }

    struct ether_header *eth = (struct ether_header *)packet;
    // Verifico che il pacchetto sia un Ethernet frame
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        fprintf(stderr, "Pacchetto non Ethernet: ether_type=%u\n", eth->ether_type);
        return flow;
    }

    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    // Verifico che il pacchetto sia un IPv4 frame
    if (ip->version != 4) {
        fprintf(stderr, "Pacchetto non IPv4: version=%u\n", ip->version);
        return flow;
    }

    uint8_t l4_proto = ip->protocol;
    // verifico che il pacchetto sia TCP o UDP
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
        fprintf(stderr, "Pacchetto non TCP/UDP: protocol=%u\n", l4_proto);
        return flow;
    }

    // IP src e dst
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;

    // Porta src e dst
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    // Supporta IPv4 con header length variabile (ihl) (IP con Opzioni)
    if (caplen < sizeof(struct ether_header) + ip->ihl * 4) {
        fprintf(stderr, "Pacchetto troppo corto (failed at ihl): caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4);
        return flow;
    }

    // Skippo il puntatore al header L4 (TCP/UDP)
    char *l4_header = (char *)(packet + sizeof(struct ether_header) + ip->ihl * 4);

    if (l4_proto == IPPROTO_TCP) {
        if (caplen < sizeof(struct ether_header) + (ip->ihl * 4) + sizeof(struct tcphdr)) {
            fprintf(stderr, "Pacchetto TCP troppo corto: caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4 + sizeof(struct tcphdr));
            return flow;
        }
        struct tcphdr *tcp = (struct tcphdr *)(l4_header);
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (l4_proto == IPPROTO_UDP) {
        if (caplen < sizeof(struct ether_header) + (ip->ihl * 4) + sizeof(struct udphdr)) {
            fprintf(stderr, "Pacchetto UDP troppo corto: caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4 + sizeof(struct udphdr));
            return flow;
        }
        struct udphdr *udp = (struct udphdr *)(l4_header);
        src_port = udp->source;
        dst_port = udp->dest;
    }

    flow.local_ip = src_ip;
    flow.remote_ip = dst_ip;
    flow.local_port = src_port;
    flow.remote_port = dst_port;
    flow.layer4_protocol = l4_proto;
    flow.offsetL3 = sizeof(struct ether_header);

    return flow;
}

/*
 * Normalizzazione da usare in produzione
 * local_ip: indirizzo IP INBOUND (in offline mode: fornito dall'utente, in online mode: ottenuto automaticamente tramite interfaccia di rete)
 */
flow_t normalize_topologic_flow(flow_nn_t nnflow, uint32_t local_ip) {
	flow_t flow = {0};

	flow.local_ip = nnflow.local_ip;
	flow.remote_ip = nnflow.remote_ip;
	flow.local_port = nnflow.local_port;
	flow.remote_port = nnflow.remote_port;
	flow.layer4_protocol = nnflow.layer4_protocol;

    if (flow.local_ip != local_ip) {
        uint32_t temp_ip = flow.local_ip;
        flow.local_ip = flow.remote_ip;
        flow.remote_ip = temp_ip;
        uint16_t temp_port = flow.local_port;
        flow.local_port = flow.remote_port;
        flow.remote_port = temp_port;
    }
    return flow;
}

/*
 * Normalizzazione usata per TESTING ONLY (perde informazioni su inbound/outbound)
 * Normalizza il flusso invertendo local/remote se necessario
 */
flow_t normalize_num_flow(flow_t flow) {
    if (flow.local_ip > flow.remote_ip || (flow.local_ip == flow.remote_ip && flow.local_port > flow.remote_port)) {
        uint32_t temp_ip = flow.local_ip;
        uint16_t temp_port = flow.local_port;
        flow.local_ip = flow.remote_ip;
        flow.remote_ip = temp_ip;
        flow.local_port = flow.remote_port;
        flow.remote_port = temp_port;
    }
    return flow;
}



// Computes direction and Markov state
static inline uint8_t get_packet_state(const flow_nn_t *flow_nn, const CaptureContext *ctx, uint32_t caplen) {
    int direction = (flow_nn->local_ip == ctx->config->local_ip) ? 1 : 0;
    return compute_markov_state(direction, caplen);
}

// Handles TLS/QUIC check and promotion logic
static inline bool check_and_promote_if_target_proto(ndpi_protocol proto, flow_t flow, ukw_flow_table_t *ukw_entry, CaptureContext *ctx) {
    if (ndpi_is_proto(proto.proto, NDPI_PROTOCOL_TLS) ||
        ndpi_is_proto(proto.proto, NDPI_PROTOCOL_QUIC)) {
        printf("[detected] flow -> TLS/QUIC\n");
        promote_ukw_to_identified(flow, ukw_entry, ctx);
        return true;
    }
    return false;
}




void train_matrix_offline_packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Casto il pointer user a CaptureContext
    CaptureContext *ctx = (CaptureContext *)user;
    ctx->total_packets++;

    uint64_t pkt_sec = pkthdr->ts.tv_sec;
    if (ctx->pcap_start_time == 0 || pkt_sec < ctx->pcap_start_time) {
        ctx->pcap_start_time = pkt_sec;
    }
    if (pkt_sec > ctx->pcap_end_time) {
        ctx->pcap_end_time = pkt_sec;
    }

    // Estraggo lunghezza e timestamp del pacchetto
    uint16_t caplen = pkthdr->caplen;
    uint64_t time_ms = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

    // Estraggo il flusso dal pacchetto
    flow_nn_t flow_nn = create_flow(caplen, packet);
    uint16_t l3offset = flow_nn.offsetL3;
    // Normalizzo il flusso
    flow_t flow = normalize_topologic_flow(flow_nn, ctx->config->local_ip);

    if (flow.layer4_protocol == 0) {
        return;
    }

    // is flow already identified?
    flow_table_t *flow_entry = find_flow(flow);
    if (flow_entry != NULL) {
        ctx->monitored_packets++;
        // Identified flow — feed packet into existing NDPI detector
        ndpi_detection_process_packet(ctx->ndpi_struct, flow_entry->ndpi_flow, packet+l3offset, caplen-l3offset, time_ms, NULL);

        uint8_t state = get_packet_state(&flow_nn, ctx, caplen);

        // Se il flusso ha completato il training, verifichiamo la probabilità di transizione (rilevamento anomalie con soglia -t / -c)
        if (flow_entry->training_done) {
            if (flow_entry->markov.last_state >= 0) {
                double current_prob[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
                normalize_markov_matrix(flow_entry->markov.transition_matrix, current_prob);
                double trans_prob = current_prob[flow_entry->markov.last_state][state];

                if (trans_prob < ctx->config->threshold) {
                    // Anomalia rilevata: transizione sotto soglia
                    flow_entry->anomaly_detected = true;
                    ctx->total_anomalies++;
                }
            }
            flow_entry->markov.last_state = (int8_t)state;
        } else {
            // Fase di Training per-flusso
            if (flow_entry->markov.last_state >= 0) {
                flow_entry->markov.transition_matrix[flow_entry->markov.last_state][state]++;
            }
            flow_entry->markov.last_state = (int8_t)state;
            flow_entry->packets_from_last_norm++;

            if (flow_entry->packets_from_last_norm >= ctx->config->norm_interval_check && 
                infinity_norm(flow_entry->markov.transition_matrix) >= 1) {
                
                double current_probability[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
                normalize_markov_matrix(flow_entry->markov.transition_matrix, current_probability);

                if (flow_entry->has_last_probability_matrix) {
                    double delta = delta_prob_norm(flow_entry->last_probability_matrix, current_probability);
                    if (delta <= ctx->config->convergence) {
                        flow_entry->training_done = true;
                        printf("[training] Flow converged and frozen!\n");
                    }
                }
                memcpy(flow_entry->last_probability_matrix, current_probability, sizeof(current_probability));
                flow_entry->has_last_probability_matrix = true;
                flow_entry->packets_from_last_norm = 0;
            }
        }

        flow_entry->packet_count++;
        flow_entry->last_seen_ms = time_ms;

        // Calcolo metriche RRD periodiche (Throttle: aggiorna RRD solo quando cambia il secondo del pacchetto)
        static uint64_t last_rrd_update_sec = 0;
        if (ctx->config->rrd_path && pkthdr->ts.tv_sec != last_rrd_update_sec) {
            last_rrd_update_sec = pkthdr->ts.tv_sec;

            flow_table_t *curr_f, *tmp_f;
            flow_table_t *head_f = get_flow_table_head();
            uint32_t active_flows = 0;
            double sum_prob = 0.0;
            int prob_count = 0;

            HASH_ITER(hh, head_f, curr_f, tmp_f) {
                active_flows++;
                double p_mat[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
                if (curr_f->has_last_probability_matrix) {
                    memcpy(p_mat, curr_f->last_probability_matrix, sizeof(p_mat));
                } else {
                    normalize_markov_matrix(curr_f->markov.transition_matrix, p_mat);
                }

                double row_sum = 0.0;
                int non_zero = 0;
                for(int i=0; i<MARKOV_STATE_SPACE; i++) {
                    for(int j=0; j<MARKOV_STATE_SPACE; j++) {
                        if (p_mat[i][j] > 0.0) {
                            row_sum += p_mat[i][j];
                            non_zero++;
                        }
                    }
                }
                if (non_zero > 0) {
                    sum_prob += (row_sum / non_zero);
                    prob_count++;
                }
            }
            double avg_prob = (prob_count > 0) ? (sum_prob / prob_count) : 0.0;
            double mon_ratio = (ctx->total_packets > 0) ? ((double)ctx->monitored_packets / ctx->total_packets) : 0.0;

            rrd_init_database(ctx->config->rrd_path, pkthdr->ts.tv_sec);
            rrd_update_metrics(ctx->config->rrd_path, pkthdr->ts.tv_sec, ctx->total_anomalies, avg_prob, active_flows, mon_ratio);
        }
    }
    else {
   		// Handles Unknown Flows (Lookup or Create)
        ukw_flow_table_t *ukw_entry = find_ukw_flow(flow);
        bool is_new_flow = (ukw_entry == NULL);

        if (is_new_flow) {
            ukw_entry = add_ukw_flow(flow);
            if (ukw_entry == NULL) return;

            ukw_entry->ndpi_flow = (struct ndpi_flow_struct *)calloc(1, sizeof(struct ndpi_flow_struct));
            if (ukw_entry->ndpi_flow == NULL) {
                fprintf(stderr, "Failed to allocate NDPI flow\n");
                return;
            }
            ukw_entry->packet_count = 0;
        }
        u_int8_t state = get_packet_state(&flow_nn, ctx, caplen);
        if (is_new_flow){
        	ukw_entry->state_buff[0] = state;
         	ukw_entry->packet_count = 1;
        }
        else {
        	ukw_entry->state_buff[ukw_entry->packet_count % NDPI_GIVEUP_THRESHOLD] = state;
         	ukw_entry->packet_count++;
        }
        ukw_entry->last_seen_ms = time_ms;

        // Feeds packet to NDPI
        ndpi_protocol proto = ndpi_detection_process_packet(ctx->ndpi_struct, ukw_entry->ndpi_flow, packet+l3offset, caplen-l3offset, time_ms, NULL);

        // Checks for promotions of give-up
        bool promoted = check_and_promote_if_target_proto(proto, flow, ukw_entry, ctx);

        if (!promoted && !is_new_flow && ukw_entry->packet_count >= NDPI_GIVEUP_THRESHOLD){
        	if(!ndpi_is_protocol_detected(proto)){
         		printf("[giveup] flow not identified, removing\n");
           		remove_ukw_flow(flow);
         	}
        }
    }
}


/*
 * Packet callback
 * Main function da eseguire per ogni pacchetto.
 * Deve contenere tutta la logica di analisi del pacchetto.
 * Deve essere thread-safe.
 * Tutti i dati in analisi devono essere nell'pointer user (pcap_context_t).
 */
void offline_packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet){
 	// Casto il pointer user a CaptureContext
    train_matrix_offline_packet_callback(user, pkthdr, packet);
}
