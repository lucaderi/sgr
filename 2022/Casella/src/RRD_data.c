#include "../include/RRD_data.h"

#include <rrd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * Copied from printf(3) man page exemples
 */
static char *make_string(const char *fmt, ...)
{
    char *buf;
    int buf_len;
    va_list ap;

    va_start(ap, fmt);
    buf_len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (buf_len < 0)
        return NULL;

    buf_len++; // For '\0'

    buf = malloc(buf_len);

    if (!buf)
        return NULL;

    va_start(ap, fmt);
    buf_len = vsnprintf(buf, buf_len + 1, fmt, ap);
    va_end(ap);

    if (buf_len < 0)
    {
        free(buf);
        return NULL;
    }

    return buf;
}

int create_RRD(char **archive_name, time_t start_time, double alpha, double beta, double gamma, double ro, unsigned short season_period, unsigned short period)
{
    char *rra_hw,
        *rra_avg,
        *ro_string,
        *gamma_string;

    int rc;

    if (!*archive_name)
        *archive_name = DFL_ARCHIVE_NAME;

    if ((rra_avg = make_string("RRA:AVERAGE:0.5:1:%d", period)) == NULL)
        return -1;

    if ((rra_hw = make_string("RRA:HWPREDICT:%d:%f:%f:%d", period, alpha, beta, season_period)) == NULL)
    {
        rc = -1;
        goto done;
    }

    const char *dataSource_rrArchive[] = {
        "DS:data:GAUGE:2d:-273.15:5000",
        rra_avg,
        rra_hw};

    if (rrd_create_r(*archive_name, SECONDS_IN_A_DAY, start_time, ARRAY_SIZE(dataSource_rrArchive), dataSource_rrArchive) != 0)
    {
        fprintf(stderr, "rrd_create_r: %s\n", rrd_get_error());
        rc = -1;
        goto done;
    }

    if ((ro_string = make_string("%f", ro)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((gamma_string = make_string("%f", gamma)) == NULL)
    {
        rc = -1;
        goto done;
    }

    char *tune_argv[] = {
        "tune",
        *archive_name,
        "-p", ro_string,
        "-n", ro_string,
        "-z", gamma_string,
        "-v", gamma_string,
        "-f", "1",
        "-w", "1",
        "-s", "0",
        "-S", "0"};

    if (rrd_tune(ARRAY_SIZE(tune_argv), tune_argv) != 0)
    {
        fprintf(stderr, "rrd_tune: %s\n", rrd_get_error());
        rc = -1;
        goto done;
    }

    rc = 0;

done:
    if (rra_avg)
        free(rra_avg);
    if (rra_hw)
        free(rra_hw);

    return rc;
}

int update_RRD(char *archive, time_t timestamp, float data)
{
    int rc;

    char *update_string;

    if (!archive || timestamp < 0)
    {
        fprintf(stderr, "Error, invalid values for updating");
        return -1;
    }

    if ((update_string = make_string("%ld:%.1f", timestamp, data)) == NULL)
        return -1;

    rc = rrd_update_r(archive, NULL, 1, (const char **)&update_string);

    if (rc != 0)
        fprintf(stderr, "rrd_update_r: %s\n", rrd_get_error());

    if (update_string)
        free(update_string);

    return rc;
}

int make_graph(char *archive, char *image, time_t end_time, float ro, unsigned short season_period)
{
    FILE *fp;

    char *start_time_string,
        *end_time_string,
        *def_buf_avg,
        *def_buf_pred,
        *def_buf_dev,
        *def_buf_fail,
        *cdef_buf_up,
        *cdef_buf_low;

    int rc = 0;

    if (!archive || end_time < 0)
        return -1;

    if (((start_time_string = make_string("end - %ld", (season_period + 2) * SECONDS_IN_A_DAY))) == NULL)
        return -1;

    if ((end_time_string = make_string("%ld", end_time - SECONDS_IN_A_DAY)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_avg = make_string("DEF:temp=%s:data:AVERAGE", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_pred = make_string("DEF:pred=%s:data:HWPREDICT", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_dev = make_string("DEF:dev=%s:data:DEVPREDICT", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_fail = make_string("DEF:fail=%s:data:FAILURES", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((cdef_buf_up = make_string("CDEF:upper=pred,dev,%f,*,+", ro)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((cdef_buf_low = make_string("CDEF:lower=pred,dev,%f,*,-", ro)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if (!image)
        image = DFL_IMAGE_NAME;

#if 1
    char *graph_argv[] = {
        "graph",
        image,
        "--end", end_time_string,
        "--start", start_time_string,
        "-w", "800",
        "-h", "300",
        "-m", "1.5",
        def_buf_avg,
        def_buf_pred,
        def_buf_dev,
        def_buf_fail,
        cdef_buf_up,
        cdef_buf_low,
        "TICK:fail#ffffa0:1.0: Anomaly",
        "LINE0.5:temp#0000ff:Average temp per day",
        "LINE1:upper#ff0000:Upper Confidence Bound",
        "LINE1:lower#ff0000:Lower Confidence Bound"};
#else
    char *graph_argv[] = {
        "graph",
        image,
        "--start", start_time_string,
        "--end", end_time_string,
        "-w", "800",
        "-h", "300",
        "-m", "1.5",
        def_buf_avg,
        "LINE0.5:temp#0000ff:Average temp per day"};
#endif
    if (rrd_graph_v(ARRAY_SIZE(graph_argv), graph_argv) == NULL)
    {
        fprintf(stderr, "rrd_graph_v: %s\n", rrd_get_error());
        rc = -1;
    }

done:
    if (start_time_string)
        free(start_time_string);
    if (end_time_string)
        free(end_time_string);
    if (def_buf_avg)
        free(def_buf_avg);
    if (def_buf_pred)
        free(def_buf_pred);
    if (def_buf_dev)
        free(def_buf_dev);
    if (def_buf_fail)
        free(def_buf_fail);
    if (cdef_buf_up)
        free(cdef_buf_up);
    if (cdef_buf_low)
        free(cdef_buf_low);

    return rc;
}