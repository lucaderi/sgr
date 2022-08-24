#include <rrd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "../include/RRD_data.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define SECONDS_IN_A_DAY 86400

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

char *create_RRD(char *archive_name, time_t start_time)
{
    const char *dataSource_rrArchive[] = {
        "DS:data:GAUGE:1d:U:U",
        "RRA:AVERAGE:0.5:1w:104w",
        "RRA:HWPREDICT:52w:0.5:0.05:52w"};

    if (rrd_create_r(archive_name ? archive_name : DFL_ARCHIVE_NAME, SECONDS_IN_A_DAY, start_time, ARRAY_SIZE(dataSource_rrArchive), dataSource_rrArchive) != 0)
    {
        fprintf(stderr, "rrd_create_r: %s\n", rrd_get_error());
        return NULL;
    }

    return archive_name ? archive_name : DFL_ARCHIVE_NAME;
}

int update_RRD(char *archive, time_t timestamp, float data)
{
    int rc;

    char *update_string;

    if (!archive || timestamp < 0 )
    {
        errno = EINVAL;
        return -1;
    }

    update_string = makeString("%ld:%.1f", timestamp, data);

    rc = 0;
    if ((rc = rrd_update_r(archive, NULL, 1, (const char **)&update_string)) != 0)
        fprintf(stderr, "rrd_update_r: %s\n", rrd_get_error());

    free(update_string);

    return rc;
}

int make_graph(char *archive, time_t start_time, time_t end_time)
{
    FILE *fp;

    char *start_time_string = NULL,
         *end_time_string = NULL,
         *def_buf_avg = NULL,
         *def_buf_pred = NULL,
         *def_buf_dev = NULL;

    int rc = 0;

    if (!archive || start_time < 0 || end_time < 0)
    {
        errno = EINVAL;
        return -1;
    }

    if ((start_time_string = makeString("%ld", start_time)) == NULL)
        return -1;

    if ((end_time_string = makeString("%ld", end_time)) == NULL)
        goto done;

    if ((def_buf_avg = makeString("DEF:temp=%s:data:AVERAGE", archive)) == NULL)
        goto done;

    if ((def_buf_pred = makeString("DEF:pred=%s:data:HWPREDICT", archive)) == NULL)
        goto done;

    if ((def_buf_dev = makeString("DEF:dev=%s:data:DEVPREDICT", archive)) == NULL)
        goto done;

    char *image_path = strdup(DFL_IMAGE_NAME);

    #if 1
    char *graph_argv[] = {
        "graph",
        image_path,
        "--start", start_time_string,
        "--end", end_time_string,
        "-w", "800",
        "-h", "300",
        "-D",
        def_buf_avg,
        def_buf_pred,
        def_buf_dev,
        "CDEF:upper=pred,dev,2,*,+",
        "CDEF:lower=pred,dev,2,*,-",
        "LINE0.5:temp#0000ff:Average temp per week",
        "LINE1:upper#ff0000:Upper Confidence Bound - Average bytes per second",
        "LINE1:lower#ff0000:Lower Confidence Bound - Average bytes per second"};
    #else
    char *graph_argv[] = {
        "graph",
        image_path,
        "--start", start_time_string,
        "--end", end_time_string,
        def_buf_avg,
        "LINE2:temp#0000ff:Average temperature per week"};
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
    if (image_path)
        free(image_path);

    return rc;
}