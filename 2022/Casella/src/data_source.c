#include "../include/data_source.h"

#define _XOPEN_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/RRD_data.h"

#define BUF_SIZE 1024
#define FREAD_BUF_SIZE 65536
#define C_TO_K(c) (c) + 273.15
#define K_TO_C(k) (k) - 273.15

static int count_lines(FILE *file)
{
    char buf[FREAD_BUF_SIZE];
    int counter = 0;
    for (;;)
    {
        size_t res = fread(buf, 1, FREAD_BUF_SIZE, file);
        if (ferror(file))
            return -1;

        int i;
        for (i = 0; i < res; i++)
            if (buf[i] == '\n')
                counter++;

        if (feof(file))
            break;
    }

    return counter;
}

static void parse_line(char *line, char **date, char **value)
{
    char *savePtr;

    strtok_r(line, ",", &savePtr); // First token is station code.

    *date = strtok_r(NULL, ",", &savePtr); // Second token is date.

    *value = strtok_r(NULL, ",", &savePtr); // Third token is average temperature of the day.
}

static int get_date_and_temp(char *line, time_t *timestamp, double *temp)
{
    char *date_string = NULL,
         *value_string = NULL;

    struct tm tm;

    double value;

    if (!line || strlen(line) == 0)
        return -1;

    parse_line(line, &date_string, &value_string);

    if (!date_string || strlen(date_string) == 0 || !value_string || strlen(value_string) == 0)
        return -1;

    memset(&tm, 0, sizeof(struct tm));
    strptime(date_string, "\"%F\"", &tm);
    tm.tm_sec = 0, tm.tm_min = 0, tm.tm_hour = 0;
    *timestamp = timegm(&tm);

    if (value_string[0] == '"')
        value_string = value_string + 1; // Remove the parenthesis at the start of the string if any

    errno = 0;
    value = strtod(value_string, NULL);

    if (errno == ERANGE)
        return -1;

    *temp = value;

    return 0;
}

static void detect_anomaly(struct ndpi_hw_struct *hw, double value, time_t timestamp, unsigned int verbose)
{
    int rc,
        is_anomaly;

    double prediction,
        confidence_band,
        lower,
        upper;
    static int print = 1;
    value = C_TO_K(value);
    value *= 100;

    rc = ndpi_hw_add_value(hw, value, &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    is_anomaly = ((rc == 0) || (confidence_band == 0) || ((value >= lower) && (value <= upper))) ? 0 : 1;

    if ((is_anomaly || verbose))
    {
        if (print)
        {
            print = 0;
            printf("%s                       %s\t%s    %s           %s\t %s     [%s]\n",
                   "When", "Value", "Prediction", "Lower", "Upper", "Out", "Band");
        }

        char buf[32];
        const time_t _t = timestamp;
        struct tm *t_info = gmtime((const time_t *)&_t);

        strftime(buf, sizeof(buf), "%d/%b/%Y %H:%M:%S", t_info);

        printf("%s %12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
               buf, K_TO_C(value / 100.), K_TO_C(prediction / 100.), K_TO_C(lower / 100.), K_TO_C(upper / 100.),
               is_anomaly ? "ANOMALY" : "OK", confidence_band / 100.);
    }
}

int read_csv(char *csv_path, struct ndpi_hw_struct *hw, char *archive, char *image)
{
    FILE *fp;

    time_t time, start_time;

    double temp;

    int rc;

    unsigned int rows;

    char buf[BUF_SIZE];

    fp = fopen(csv_path, "r");

    if (!fp)
        return -1;

    rows = count_lines(fp) - 1;

    if (rows == -1)
    {
        fprintf(stderr, "Error while counting file %s rows\n", csv_path);
        rc = -1;
        goto done;
    }

    rewind(fp);

    if (fgets(buf, BUF_SIZE, fp) == NULL) // Get rid of the first line
    {
        fprintf(stderr, "Error reading parameters line\n");
        rc = -1;
        goto done;
    }

    rc = 0;
    unsigned int i = 0;
    while (fgets(buf, BUF_SIZE, fp) != NULL && i < rows)
    {
        if (get_date_and_temp(buf, &time, &temp) != 0)
        {
            fprintf(stderr, "Error parsing date and temperature\n");
            rc = -1;
            goto done;
        }

        if (i == 0)
        {
            start_time = time - SECONDS_IN_A_DAY;

            if (create_RRD(archive, start_time, (*hw).params.alpha, (*hw).params.beta, (*hw).params.gamma, (*hw).params.ro, ((*hw).params.num_season_periods + 1) / 2, rows) == -1)
            {
                fprintf(stderr, "Error creating rrd archive");
                rc = -1;
                goto done;
            }
        }

        if (update_RRD(archive, time, temp) != 0)
        {
            fprintf(stderr, "Error updating rrd archive %s\n", archive);
            rc = -1;
            goto done;
        }

        detect_anomaly(hw, temp, time, 0);
        i++;
    }

    if (ferror(fp) != 0)
    {
        fprintf(stderr, "Error reading file\n");
        rc = -1;
        goto done;
    }

    if (make_graph(archive, image, time, (*hw).params.ro, ((*hw).params.num_season_periods + 1) / 2) == -1)
    {
        rc = -1;
        fprintf(stderr, "Unable to create graph\n");
    }

done:
    fclose(fp);

    return rc;
}