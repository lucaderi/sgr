// header.h
// Se NDPI_HEADER_H non ancora definito, lo definisco
#ifndef NDPI_HEADER_H 
#define NDPI_HEADER_H

#include <stdint.h>

// Struttura di analisi
struct ndpi_analyze_struct;

// Funzioni disponibili
struct ndpi_analyze_struct* ndpi_alloc_data_analysis(uint16_t _max_series_len);
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const uint64_t value);
float ndpi_data_mean(struct ndpi_analyze_struct *s);
float ndpi_data_stddev(struct ndpi_analyze_struct *s);
uint64_t ndpi_data_min(struct ndpi_analyze_struct *s);
uint64_t ndpi_data_max(struct ndpi_analyze_struct *s);
void ndpi_free_data_analysis(struct ndpi_analyze_struct *d, uint8_t free_pointer);

#endif // NDPI_HEADER_H
