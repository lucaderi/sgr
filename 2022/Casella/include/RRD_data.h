#ifndef RDD_DATA_H
#define RDD_DATA_H

#include <time.h>

#define DFL_ARCHIVE_NAME "monitor.rrd"
#define DFL_IMAGE_NAME "graph.png"

char *create_RRD(char *archive_name, time_t start_time);
int update_RRD(char *archive, time_t timestamp, float data);
int make_graph(char *archive, time_t start_time, time_t end_time);
#endif