#ifndef RRD_REPORTER_H
#define RRD_REPORTER_H

#include "common.h"

int rrd_init_database(const char *rrd_path, uint64_t start_time_sec);
void rrd_update_metrics(const char *rrd_path, uint64_t timestamp_sec, uint32_t total_anomalies, double avg_probability, uint32_t active_flows_count, double monitored_ratio);
void generate_rrd_graphs(const char *rrd_path, uint64_t start_time_sec, uint64_t end_time_sec);

#endif
