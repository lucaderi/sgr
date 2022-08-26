#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include "../include/data_source.h"

#define DEFAULT_ALPHA 0.1
#define DEFAULT_BETA 0.0032
#define DEFAULT_GAMMA 0.1
#define DEFAULT_RO 0.05
#define DEFAULT_SEASONAL_PERIOD 729 // 2 years
#define DEFAULT_PERIOD 1097 // 3 years

void help()
{
    printf(
        "-f filename            Path to cvs file with data source" \
        "-d archive             Name for rrd archive" \
        "-i image               Name for rrdtool graph" \
        "-a alpha               Set alpha parameter for Holt-Winters algorithm. Valid range 0 > .. < 1" \
        "-b beta                Set beta parameter for Holt-Winters algorithm. Valid range 0 > .. < 1" \
        "-g gamma               Set gamma parameter for Holt-Winters algorithm. Valid range 0 > .. < 1" \
        "-r ro                  Set significance parameter for Holt-Winters algorithm. Valid range 0 > .. < 1" \
        "-s seasonal_period     Set seasonal_period length for Holt-Winters algorithm." \
        "-p period              Set length in days of the portion of data to read."
    );
}
int main(int argc, char *argv[])
{
    char opt;

    char *filename = NULL,
        *archive = NULL,
        *image = NULL;

    struct ndpi_hw_struct hw;

    int seasonal_period,
        period;

    float alpha, beta, gamma, ro;

    alpha = DEFAULT_ALPHA;
    beta = DEFAULT_BETA;
    gamma = DEFAULT_GAMMA;
    ro = DEFAULT_RO;
    seasonal_period = DEFAULT_SEASONAL_PERIOD;
    period = DEFAULT_PERIOD;

    while ((opt = getopt(argc, argv, "f:d:i:a:b:g:s:p:r:h")) != -1)
    {
        switch (opt)
        {
        case 'f':
            filename = optarg;
            break;
        case 'd':
            filename = optarg;
            break;
        case 'i':
            filename = optarg;
            break;
        case 'a':
            alpha = atof(optarg);
            if ((alpha <= 0) && (alpha >= 1))
                alpha = DEFAULT_ALPHA;
            break;
        case 'b':
            beta = atof(optarg);
            if ((beta <= 0) && (beta >= 1))
                beta = DEFAULT_BETA;
            break;
        case 'g':
            gamma = atof(optarg);
            if ((gamma <= 0) && (gamma >= 1))
                gamma = DEFAULT_GAMMA;
            break;
        case 's':
            seasonal_period = atoi(optarg);
            if (seasonal_period <= 0)
                seasonal_period = DEFAULT_SEASONAL_PERIOD;
            break;
        case 'p':
            period = atoi(optarg);
            if (period <= 0)
                period = DEFAULT_PERIOD;
        case 'r':
            ro = atof(optarg);
            if ((ro <= 0) && (ro >= 1))
                ro = DEFAULT_RO;
            break;
        case 'h':
            help();
            break;
        default:
            fprintf(stderr, "Unkwon command line option -%c\n", opt);
            break;
        }
    }

    if (!filename)
    {
        help();
        exit(EXIT_FAILURE);
    }

    ndpi_hw_init(&hw, seasonal_period, 1, alpha, beta, gamma, ro); // 1 additive : 0 multiplicative

    read_csv(filename, &hw, period, archive, image);

    ndpi_hw_free(&hw);

    return 0;
}