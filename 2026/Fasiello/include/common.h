#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/types.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <uthash.h>

#define MARKOV_STATE_SPACE 12

// Forward declaration — full definition is in ndpi_api.h, included by consumers
struct ndpi_flow_struct;

#define NDPI_GIVEUP_THRESHOLD 16

/* Sposta Config,init config,free config in un file header comune
 * Gestisce le opzioni utente
 *
 */
typedef struct {
    char *pcap_file;
    uint32_t local_ip;
    char *rrd_path;
    double threshold;
    double convergence;
    uint32_t max_flows;
    char *filter;
    uint32_t norm_interval_check;
} Config;

// Modello markoviano per singolo flusso
typedef struct {
    uint32_t transition_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
    int8_t last_state;                  // Ultimo stato visto nel flusso (-1 all'avvio)
} markov_model_t;

// Anche questo va nel coso comune
typedef struct{
    pcap_t *handle;
    Config *config;
    struct ndpi_detection_module_struct *ndpi_struct;   // ndpi?
    // altri dati da mettere nel detector vanno qui
    bool training_done;
    uint32_t total_packets;
    uint32_t monitored_packets;
    uint32_t total_anomalies;
    uint64_t pcap_start_time;
    uint64_t pcap_end_time;
} CaptureContext;

// Struct per identificare univocamente un flusso (only IPV4)
typedef struct {
    uint8_t layer4_protocol;    // Protocollo L4 (TCP/UDP)
    uint32_t local_ip;            // IP sorgente (network order)
    uint32_t remote_ip;            // IP destinazione (network order)
    uint16_t local_port;          // Porta sorgente (network order)
    uint16_t remote_port;          // Porta destinazione (network order)
} flow_t;

// Struct per flussi, include offset to layer3 richiesto da process_packet (only IPV4)
typedef struct {
    uint8_t layer4_protocol;    // Protocollo L4 (TCP/UDP)
    uint32_t local_ip;            // IP sorgente (network order)
    uint32_t remote_ip;            // IP destinazione (network order)
    uint16_t local_port;          // Porta sorgente (network order)
    uint16_t remote_port;          // Porta destinazione (network order)
    uint16_t offsetL3;			// Offset to the beginning of layer 3
} flow_nn_t;

// Struct per tabella hash dei flussi identificati
typedef struct {
    flow_t key;                            // chiave per la tabella hash
    struct ndpi_flow_struct *ndpi_flow;    // stato flusso NDPI

    uint32_t packet_count;                  // Numero di pacchetti
    uint32_t last_seen_ms;                  // Timestamp dell'ultimo pacchetto ricevuto

    // Modello Markoviano e stato di training per-flusso
    markov_model_t markov;
    uint32_t packets_from_last_norm;
    double last_probability_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE];
    bool has_last_probability_matrix;
    bool training_done;
    bool anomaly_detected;                  // Flag o contatore di anomalie

    UT_hash_handle hh;
} flow_table_t;

// Struct per tabella hash dei flussi inidentificati
typedef struct {
	flow_t key;
	struct ndpi_flow_struct *ndpi_flow;

	uint8_t state_buff[NDPI_GIVEUP_THRESHOLD];           // Memorizza direttamente lo stato S (0-11)
	uint32_t packet_count;                   		     // Numero di pacchetti
    uint32_t last_seen_ms;                   		     // Timestamp dell'ultimo pacchetto ricevuto
    UT_hash_handle hh;

} ukw_flow_table_t;



void init_config(Config *config);
void free_config(Config *config);
int init_ndpi_engine(CaptureContext *ctx);
void cleanup_context(CaptureContext *ctx);

#endif
