#include "rrd_reporter.h"
#include <rrd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <unistd.h>

int rrd_init_database(const char *rrd_path, uint64_t start_time_sec) {
    char tmp[512];
    strncpy(tmp, rrd_path, sizeof(tmp));
    char *dir = dirname(tmp);
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dir);
    system(mkdir_cmd);

    struct stat st;
    if (stat(rrd_path, &st) == 0) {
        return 0;
    }

    char start_str[64];
    snprintf(start_str, sizeof(start_str), "%lu", (unsigned long)(start_time_sec > 0 ? start_time_sec - 1 : 0));

    const char *argv[] = {
        "rrdcreate",
        (char *)rrd_path,
        "--step", "1",
        "--start", start_str,
        "DS:anomalies:GAUGE:60:0:U",
        "DS:avg_prob:GAUGE:60:0:100",
        "DS:active_flows:GAUGE:60:0:U",
        "DS:mon_ratio:GAUGE:60:0:100",
        "RRA:AVERAGE:0.5:1:86400",
        "RRA:MAX:0.5:1:86400",
        NULL
    };

    optind = 0;
    int argc = 0;
    while (argv[argc] != NULL) argc++;

    int ret = rrd_create(argc, (const char **)argv);
    if (ret != 0) {
        fprintf(stderr, "Errore nella creazione del database RRD (%s): %s\n", rrd_path, rrd_get_error());
        rrd_clear_error();
        return -1;
    }

    printf("[RRD] Database RRD creato con successo in: %s (start: %lu)\n", rrd_path, (unsigned long)start_time_sec);
    return 0;
}

void rrd_update_metrics(const char *rrd_path, uint64_t timestamp_sec, uint32_t total_anomalies, double avg_probability, uint32_t active_flows_count, double monitored_ratio) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%lu:%u:%.6f:%u:%.6f", 
             (unsigned long)timestamp_sec, 
             total_anomalies, 
             avg_probability * 100.0, 
             active_flows_count, 
             monitored_ratio * 100.0);

    const char *argv[] = {
        "rrdupdate",
        (char *)rrd_path,
        buf,
        NULL
    };

    optind = 0;
    int argc = 0;
    while (argv[argc] != NULL) argc++;

    int ret = rrd_update(argc, (const char **)argv);
    if (ret != 0) {
        rrd_clear_error();
    }
}

void generate_rrd_graphs(const char *rrd_path, uint64_t start_time_sec, uint64_t end_time_sec) {
    uint64_t duration = (end_time_sec > start_time_sec) ? (end_time_sec - start_time_sec) : 60;
    uint64_t graph_end = start_time_sec + duration + 5;
    uint64_t graph_start = (start_time_sec > 5) ? (start_time_sec - 5) : 0;

    char cmd[2560];

    // 1. Monitored Traffic Ratio Graph
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/rrdtool graph test/out/monitored_traffic.png "
        "--title 'Monitored Traffic Ratio' "
        "--vertical-label 'Percentage (%%)' "
        "--start %lu --end %lu "
        "--width 600 --height 200 "
        "DEF:ratio=%s:mon_ratio:AVERAGE "
        "LINE2:ratio#00FF00:'Monitored Ratio (%%)'",
        (unsigned long)graph_start, (unsigned long)graph_end, rrd_path);
    int r1 = system(cmd);

    // 2. Active Flows Count Graph
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/rrdtool graph test/out/active_flows.png "
        "--title 'Active Monitored Flows' "
        "--vertical-label 'Flow Count' "
        "--start %lu --end %lu "
        "--width 600 --height 200 "
        "DEF:flows=%s:active_flows:AVERAGE "
        "LINE2:flows#0000FF:'Active Flows Count'",
        (unsigned long)graph_start, (unsigned long)graph_end, rrd_path);
    int r2 = system(cmd);

    // 3. Average Transition Probability Graph (Y-axis rigid 0 to 100)
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/rrdtool graph test/out/average_probability.png "
        "--title 'Markov Average Transition Probability' "
        "--vertical-label 'Probability (%%)' "
        "--start %lu --end %lu "
        "--width 600 --height 200 "
        "--lower-limit 0 --upper-limit 100 --rigid "
        "DEF:prob=%s:avg_prob:AVERAGE "
        "LINE2:prob#FF6600:'Avg Transition Probability (%%)'",
        (unsigned long)graph_start, (unsigned long)graph_end, rrd_path);
    int r3 = system(cmd);

    // 4. Anomalous Transitions Graph
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/rrdtool graph test/out/anomalies.png "
        "--title 'Detected Anomalous State Transitions' "
        "--vertical-label 'Anomalies Count' "
        "--start %lu --end %lu "
        "--width 600 --height 200 "
        "DEF:anom=%s:anomalies:AVERAGE "
        "AREA:anom#FF000033:'Anomalies Area' "
        "LINE2:anom#FF0000:'Cumulative Anomalies'",
        (unsigned long)graph_start, (unsigned long)graph_end, rrd_path);
    int r4 = system(cmd);

    printf("[RRD] Grafici PNG separati generati in test/out/ [start: %lu, end: %lu] (status: %d, %d, %d, %d)\n", 
           (unsigned long)graph_start, (unsigned long)graph_end, r1, r2, r3, r4);
}
