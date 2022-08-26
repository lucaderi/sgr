#include "../include/RRD_data.h"

#include <rrd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * Copied from printf(3) man page exemples
 */
static char *makeString(const char *fmt, ...)
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

char *create_RRD(char *archive_name, time_t start_time, struct ndpi_hw_struct hw, int period)
{
    char *rra_hw,
        *rra_avg,
        *ro_string,
        *gamma_string;

    int period_weeks = period / 7;
    int weeks = hw.params.num_season_periods / 7;

    if ((rra_avg = makeString("RRA:AVERAGE:0.5:1w:%dw", period_weeks)) == NULL)
        return NULL;

    if ((rra_hw = makeString("RRA:HWPREDICT:%dw:%f:%f:%dw", period_weeks - weeks, hw.params.alpha, hw.params.beta, weeks)) == NULL)
        return NULL;

    const char *dataSource_rrArchive[] = {
        "DS:data:GAUGE:1d:U:U",
        rra_avg,
        rra_hw};

    if (rrd_create_r(archive_name ? archive_name : DFL_ARCHIVE_NAME, SECONDS_IN_A_DAY, start_time, ARRAY_SIZE(dataSource_rrArchive), dataSource_rrArchive) != 0)
    {
        fprintf(stderr, "rrd_create_r: %s\n", rrd_get_error());
        return NULL;
    }

    ro_string = makeString("%f", hw.params.ro);
    gamma_string = makeString("%f", hw.params.gamma);

    char *tune_argv[] = {
        "tune",
        archive_name ? archive_name : DFL_ARCHIVE_NAME,
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
        fprintf(stderr, "rrd_graph_v: %s\n", rrd_get_error());
    }

    free(rra_avg);
    free(rra_hw);

    return archive_name ? archive_name : DFL_ARCHIVE_NAME;
}

int update_RRD(char *archive, time_t timestamp, float data)
{
    int rc;

    char *update_string;

    if (!archive || timestamp < 0)
        return -1;

    update_string = makeString("%ld:%.1f", timestamp, data);

    rc = rrd_update_r(archive, NULL, 1, (const char **)&update_string);

    if (rc != 0)
        fprintf(stderr, "rrd_update_r: %s\n", rrd_get_error());

    free(update_string);

    return rc;
}

int make_graph(char *archive, char *image, time_t start_time, time_t end_time, float ro, int is_addative)
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

    if (!archive || start_time < 0 || end_time < 0)
    {
        errno = EINVAL;
        return -1;
    }

    if ((start_time_string = makeString("%ld", start_time)) == NULL)
        return -1;

    if ((end_time_string = makeString("%ld", end_time)) == NULL)
    {
        rc = -1;
        goto done;
    }
        

    if ((def_buf_avg = makeString("DEF:temp=%s:data:AVERAGE", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_pred = makeString("DEF:pred=%s:data:HWPREDICT", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_dev = makeString("DEF:dev=%s:data:DEVPREDICT", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((def_buf_fail = makeString("DEF:fail=%s:data:FAILURES", archive)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((cdef_buf_up = makeString("CDEF:upper=pred,dev,%f,*,+", ro)) == NULL)
    {
        rc = -1;
        goto done;
    }

    if ((cdef_buf_low = makeString("CDEF:lower=pred,dev,%f,*,-", ro)) == NULL)
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
        "--start", start_time_string,
        "--end", end_time_string,
        "-w", "800",
        "-h", "300",
        def_buf_avg,
        def_buf_pred,
        def_buf_dev,
        def_buf_fail,
        cdef_buf_up,
        cdef_buf_low,
        "TICK:fail#03fc49:1.0: Failure",
        "LINE0.5:temp#0000ff:Average temp per week",
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
        def_buf_avg,
        def_buf_pred,
        def_buf_dev,
        cdef_buf_up,
        cdef_buf_low,
        "CDEF:exceeds=temp,UN,0,temp,lower,upper,LIMIT,UN,IF",
        "TICK:exceeds#7ab4ff:1: Anomaly",
        "LINE0.5:temp#0000ff:Average temp per week",
        "LINE1:upper#ff0000:Upper Confidence Bound",
        "LINE1:lower#ff0000:Lower Confidence Bound"};
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