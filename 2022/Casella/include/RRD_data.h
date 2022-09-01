#ifndef RDD_DATA_H
#define RDD_DATA_H

#include <time.h>

#define DFL_ARCHIVE_NAME "weather.rrd"
#define DFL_IMAGE_NAME "graph.png"
#define SECONDS_IN_A_DAY 86400

int create_RRD(char **archive_name, time_t start_time, double alpha, double beta, double gamma, double ro, unsigned short season_period, unsigned short period);
int update_RRD(char *archive, time_t timestamp, float data);
int make_graph(char *archive, char *image, time_t end_time, float ro, unsigned short season_period);
#endif