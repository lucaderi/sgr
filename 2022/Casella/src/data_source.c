#define _XOPEN_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/data_source.h"
#include "../include/RRD_data.h"

#define BUF_SIZE 1024

#define TM_TO_SECONDS(tm, time) \
    tm.tm_sec = 0;              \
    tm.tm_min = 0;              \
    tm.tm_hour = 12;            \
    time = tm.tm_sec + tm.tm_min * 60 + tm.tm_hour * 3600 + tm.tm_yday * 86400 + (tm.tm_year - 70) * 31536000 + ((tm.tm_year - 69) / 4) * 86400 - ((tm.tm_year - 1) / 100) * 86400 + ((tm.tm_year + 299) / 400) * 86400

static void get_date_and_value(char *line, char **date, char **value)
{
    char *savePtr;

    strtok_r(line, ",", &savePtr); // First token in station code.

    *date = strtok_r(NULL, ",", &savePtr);

    *value = strtok_r(NULL, ",", &savePtr);
}

int read_csv(char *csv_path)
{
    FILE *fp;

    struct tm tm;
    time_t time, start_time;

    int rc;

    char *date, *value, *archive = NULL, *endPtr = NULL;

    fp = fopen(csv_path, "r");

    if (!fp)
        return -1;

    char buf[1024];

    if (fgets(buf, BUF_SIZE, fp) == NULL)
    {
        fprintf(stderr, "Error reading parameters line\n");
        rc = -1;
        goto done;
    }

    rc = 0;
    while (fgets(buf, BUF_SIZE, fp) != NULL)
    {
        date = value = NULL;

        get_date_and_value(buf, &date, &value);

        strptime(date, "\"%Y-%m-%d\"", &tm);
        TM_TO_SECONDS(tm, time);
        if (!archive)
        {
            start_time = time - 86400;
            archive = create_RRD(NULL, start_time);
        }

        value[strlen(value) - 2] = '\0';
        value = value + 1;
        float temp = strtof(value, &endPtr);
        update_RRD(archive, time, temp);
    }

    if (ferror(fp) != 0)
    {
        fprintf(stderr, "Error reading file\n");
        rc = -1;
        goto done;
    }

done:
    fclose(fp);

    printf("start_time: %ld\nend_time: %ld\n", start_time, time);
    make_graph(archive, start_time, time);

    return rc;
}