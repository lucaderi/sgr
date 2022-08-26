#include "../include/data_source.h"

#define _XOPEN_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/RRD_data.h"

#define BUF_SIZE 1024
#define SECONDS_IN_A_YEAR 60*60*24*365
#define C_TO_K(c) (c) + 273.15
#define K_TO_C(k) (k) - 273.15

#define TM_TO_SECONDS(tm, time) \
    tm.tm_sec = 0;              \
    tm.tm_min = 0;              \
    tm.tm_hour = 12;            \
    time = tm.tm_sec + tm.tm_min * 60 + tm.tm_hour * 3600 + tm.tm_yday * 86400 + (tm.tm_year - 70) * 31536000 + ((tm.tm_year - 69) / 4) * 86400 - ((tm.tm_year - 1) / 100) * 86400 + ((tm.tm_year + 299) / 400) * 86400

static void parse_line(char *line, char **date, char **value)
{
    char *savePtr;

    strtok_r(line, ",", &savePtr); // First token is station code.

    *date = strtok_r(NULL, ",", &savePtr);

    *value = strtok_r(NULL, ",", &savePtr);
}

static int get_date_and_temp(char *line, time_t *timestamp, float *temp)
{
    char *date_string = NULL,
         *value_string = NULL;

    struct tm tm;

    float value;

    if (!line || strlen(line) == 0)
        return -1;

    parse_line(line, &date_string, &value_string);

    if (!date_string || strlen(date_string) == 0 || !value_string || strlen(value_string) == 0)
        return -1;
    
    memset(&tm, 0, sizeof(struct tm));
    strptime(date_string, "\"%F\"", &tm);

    TM_TO_SECONDS(tm, *timestamp);

    if (value_string[0] == '"');
    value_string = value_string + 1; // Remove the parenthesis at the start of the string if any

    errno = 0;
    value = strtof(value_string, NULL);

    if (errno == ERANGE)
        return -1;

    *temp = value;

    return 0;
}

static void detect_anomaly(struct ndpi_hw_struct *hw, float value, time_t timestamp, int *first)
{
    int rc,
        is_anomaly;

    double prediction,
        confidence_band,
        lower,
        upper;

    value = C_TO_K(value);
    value *= 100;

    rc = ndpi_hw_add_value(hw, value, &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    is_anomaly = ((rc == 0) || (confidence_band == 0) || ((value >= lower) && (value <= upper))) ? 0 : 1;

    if (is_anomaly)
    {
        if (*first)
        {
            *first = 0;
            printf("%s                       %s\t%s    %s           %s\t %s     [%s]\n",
                   "When", "Value", "Prediction", "Lower", "Upper", "Out", "Band");
        }

        char buf[32];
        const time_t _t = timestamp;

        struct tm *t_info = localtime((const time_t *)&_t);

        strftime(buf, sizeof(buf), "%d/%b/%Y %H:%M:%S", t_info);

        printf("%s %12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
               buf, K_TO_C(value / 100.), K_TO_C(prediction / 100.), K_TO_C(lower / 100.), K_TO_C(upper / 100.), is_anomaly ? "ANOMALY" : "OK", confidence_band / 100.);
    }
}
int read_csv(char *csv_path, struct ndpi_hw_struct *hw, int period, char *archive, char *image)
{
    FILE *fp;

    time_t time, start_time;

    float temp;

    int rc,
        first = 1;

    char buf[1024];

    fp = fopen(csv_path, "r");

    if (!fp)
        return -1;

    if (fgets(buf, BUF_SIZE, fp) == NULL)
    {
        fprintf(stderr, "Error reading parameters line\n");
        rc = -1;
        goto done;
    }

    rc = 0;
    int i = 0;
    while (fgets(buf, BUF_SIZE, fp) != NULL && i < period)
    {
        if (get_date_and_temp(buf, &time, &temp) != 0)
        {
            rc = -1;
            goto done;
        }

        if (!archive)
        {
            start_time = time - SECONDS_IN_A_DAY;
            archive = create_RRD(NULL, start_time, *hw, period);
        }

        if (update_RRD(archive, time, temp) != 0)
        {
            rc = -1;
            goto done;
        }

        detect_anomaly(hw, temp, time, &first);
        i++;
    }

    if (ferror(fp) != 0)
    {
        fprintf(stderr, "Error reading file\n");
        rc = -1;
        goto done;
    }

    make_graph(archive, image, start_time, time, (*hw).params.ro, (*hw).params.use_hw_additive_seasonal);

done:
    fclose(fp);

    return rc;
}