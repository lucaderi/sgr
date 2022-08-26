#ifndef RDD_DATA_H
#define RDD_DATA_H

#include <ndpi_api.h>
#include <time.h>

#define DFL_ARCHIVE_NAME "monitor.rrd"
#define DFL_IMAGE_NAME "graph.png"
#define SECONDS_IN_A_DAY 86400

char *create_RRD(char *archive_name, time_t start_time, struct ndpi_hw_struct hw, int period);
int update_RRD(char *archive, time_t timestamp, float data);
int make_graph(char *archive, char *image, time_t start_time, time_t end_time, float ro, int is_addative);
#endif