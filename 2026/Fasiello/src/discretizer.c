// this should discretize packet from ingester
// also handle identified flow data structure
#include "discretizer.h"
#include "common.h"
#include "ndpi_api.h"
#include <stdint.h>


// Global Identified flow table head
static flow_table_t *flow_table = NULL;

/*
 * Find a flow entry in the identified flow table
 *
 * @param key The flow key to search for
 * @return A pointer to the flow entry, or NULL if not found
 */
flow_table_t *find_flow(flow_t key) {
    flow_table_t *entry = NULL;
    HASH_FIND(hh, flow_table, &key, sizeof(flow_t), entry);
    return entry;
}

/*
 * Add a flow entry to the identified flow table
 *
 * @param key The flow key to add
 * @param ndpi_flow The ndpi flow to associate with the key
 * @return A pointer to the flow entry
 */
flow_table_t *add_flow(flow_t key, struct ndpi_flow_struct *ndpi_flow) {
    flow_table_t *entry = NULL;
    HASH_FIND(hh, flow_table, &key, sizeof(flow_t), entry);
    if (entry == NULL) {
        entry = (flow_table_t *)malloc(sizeof(flow_table_t));
        if (entry == NULL) {
            fprintf(stderr, "Failed to allocate memory for flow entry\n");
            return NULL;
        }
        memset(entry, 0, sizeof(flow_table_t));
        entry->key = key;
        entry->ndpi_flow = ndpi_flow;
        entry->markov.last_state = -1;
        HASH_ADD(hh, flow_table, key, sizeof(flow_t), entry);
    }
    else {
        entry->ndpi_flow = ndpi_flow;
    }
    return entry;
}

/*
 * Remove a flow entry from the identified flow table
 *
 * @param key The flow key to remove
 */
void remove_flow(flow_t key) {
    flow_table_t *entry = find_flow(key);
    if (entry != NULL) {
        HASH_DEL(flow_table, entry);
        if (entry->ndpi_flow != NULL) {
            ndpi_free_flow(entry->ndpi_flow);
        }
        free(entry);
    }
}

flow_table_t *get_flow_table_head(void) {
    return flow_table;
}

/*
 * Compute the Markov state from packet direction and caplen
 *
 * @param direction 1 if outbound (src_ip == local_ip), 0 if inbound
 * @param caplen     packet length
 * @return State ID (0-11)
 */
uint8_t compute_markov_state(int direction, uint16_t caplen) {
    int size_bin;
    if (caplen <= 64)   size_bin = 0;
    else if (caplen <= 128) size_bin = 1;
    else if (caplen <= 256) size_bin = 2;
    else if (caplen <= 512) size_bin = 3;
    else if (caplen <= 1024) size_bin = 4;
    else size_bin = 5;

    return (uint8_t)((direction * 6) + size_bin);
}

/*
 * Infinity Norm for the Markov transition count matrix
 * (assumes the elements are always >= 0 since is counting)
 * @param count_matrix	Transition matrix
 * @return infinity_norm
 */
uint64_t infinity_norm(uint32_t count_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE]){
	uint64_t max_row = 0;
	for(int i = 0; i < MARKOV_STATE_SPACE; i++){
		uint64_t curr_row = 0;
		for(int j = 0; j < MARKOV_STATE_SPACE; j++){
			curr_row += count_matrix[i][j];
		}
		if (curr_row >= max_row){
			max_row = curr_row;
		}
	}
	return max_row;
}

/*
 * Infinity norm of the difference between two probability matrices ||A - B||_inf
 * (assumes the elements are always >= 0)
 * @param A	double matrix
 * @param B	double matrix
 * @return infinity_norm
 */
double delta_prob_norm(double a[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE], double b[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE]){
	double max_row_sum = 0.0;

    for (int i = 0; i < MARKOV_STATE_SPACE; i++) {
        double current_row_sum = 0.0;
        for (int j = 0; j < MARKOV_STATE_SPACE; j++) {
            current_row_sum += fabs(a[i][j] - b[i][j]);
        }
        if (current_row_sum > max_row_sum) {
            max_row_sum = current_row_sum;
        }
    }

    return max_row_sum;
}

/*
 * Normalize the Markov transition count matrix into a probability matrix
 *
 * @param count_matrix   Raw transition counts (input)
 * @param prob_matrix    Normalized transition probabilities (output)
 */
void normalize_markov_matrix(const uint32_t count_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE],
                             double prob_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE]) {
    for (int i = 0; i < MARKOV_STATE_SPACE; i++) {
        uint32_t row_total = 0;
        for (int j = 0; j < MARKOV_STATE_SPACE; j++) {
            row_total += count_matrix[i][j];
        }

        for (int j = 0; j < MARKOV_STATE_SPACE; j++) {
            if (row_total > 0) {
                prob_matrix[i][j] = (double)count_matrix[i][j] / row_total;
            } else {
                prob_matrix[i][j] = 0.0;
            }
        }
    }
}

/*
 * Unknown flow table — global head
 */
static ukw_flow_table_t *ukw_flow_table = NULL;

ukw_flow_table_t *find_ukw_flow(flow_t key) {
    ukw_flow_table_t *entry = NULL;
    HASH_FIND(hh, ukw_flow_table, &key, sizeof(flow_t), entry);
    return entry;
}

ukw_flow_table_t *add_ukw_flow(flow_t key) {
    ukw_flow_table_t *entry = NULL;
    HASH_FIND(hh, ukw_flow_table, &key, sizeof(flow_t), entry);
    if (entry == NULL) {
        entry = (ukw_flow_table_t *)malloc(sizeof(ukw_flow_table_t));
        if (entry == NULL) {
            fprintf(stderr, "Failed to allocate memory for unknown flow entry\n");
            return NULL;
        }
        memset(entry, 0, sizeof(ukw_flow_table_t));
        entry->key = key;
        HASH_ADD(hh, ukw_flow_table, key, sizeof(flow_t), entry);
    }
    return entry;
}

void remove_ukw_flow(flow_t key) {
    ukw_flow_table_t *entry = find_ukw_flow(key);
    if (entry != NULL) {
        HASH_DEL(ukw_flow_table, entry);
        if (entry->ndpi_flow != NULL) {
            ndpi_free_flow(entry->ndpi_flow);
        }
        free(entry);
    }
}

flow_table_t *promote_ukw_to_identified(flow_t key, ukw_flow_table_t *ukw_entry) {
    // Remove from unknown table first
    HASH_DEL(ukw_flow_table, ukw_entry);

    // Add to identified flow table
    flow_table_t *flow_entry = add_flow(key, ukw_entry->ndpi_flow);

    // Seed the per-flow Markov model with states accumulated in the buffer
    if (flow_entry != NULL && ukw_entry->packet_count > 1) {
        for (uint32_t i = 1; i < ukw_entry->packet_count; i++) {
            uint8_t prev = ukw_entry->state_buff[(i - 1) % NDPI_GIVEUP_THRESHOLD];
            uint8_t curr = ukw_entry->state_buff[i % NDPI_GIVEUP_THRESHOLD];
            flow_entry->markov.transition_matrix[prev][curr]++;
        }
        flow_entry->markov.last_state = (int8_t)ukw_entry->state_buff[(ukw_entry->packet_count - 1) % NDPI_GIVEUP_THRESHOLD];
    }

    // Free the ukw_entry struct — its ndpi_flow was transferred to flow_table
    free(ukw_entry);

    return flow_entry;
}

void cleanup_flows(void) {
    flow_table_t *current_flow, *tmp_flow;
    HASH_ITER(hh, flow_table, current_flow, tmp_flow) {
        HASH_DEL(flow_table, current_flow);
        if (current_flow->ndpi_flow != NULL) {
            ndpi_free_flow(current_flow->ndpi_flow);
        }
        free(current_flow);
    }
    flow_table = NULL;

    ukw_flow_table_t *current_ukw, *tmp_ukw;
    HASH_ITER(hh, ukw_flow_table, current_ukw, tmp_ukw) {
        HASH_DEL(ukw_flow_table, current_ukw);
        if (current_ukw->ndpi_flow != NULL) {
            ndpi_free_flow(current_ukw->ndpi_flow);
        }
        free(current_ukw);
    }
    ukw_flow_table = NULL;
}
