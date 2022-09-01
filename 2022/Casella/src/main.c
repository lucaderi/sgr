#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/data_source.h"

#define DEFAULT_ALPHA 0.1
#define DEFAULT_BETA 0.05
#define DEFAULT_GAMMA 0.1
#define DEFAULT_RO 0.05

void help()
{
    printf(
        "Usage: ./bin/weather_anomaly -f <path-to-cvs-file> -s <season-period> [OPTIONS]\n\n"
        "Options: \n"
        "-f filename            Path to cvs file with data source\n"
        "-d archive             Name for rrd archive\n"
        "-i image               Name for rrdtool graph\n"
        "-a alpha               Set alpha parameter for Holt-Winters algorithm. Valid range 0 > .. < 1\n"
        "-b beta                Set beta parameter for Holt-Winters algorithm. Valid range 0 > .. < 1\n"
        "-g gamma               Set gamma parameter for Holt-Winters algorithm. Valid range 0 > .. < 1\n"
        "-r ro                  Set significance parameter for Holt-Winters algorithm. Valid range 0 > .. < 1\n"
        "-s seasonal_period     Set seasonal_period length for Holt-Winters algorithm.\n"
        "-p period              Set length in days of the portion of data to read.\n\n");
}
int main(int argc, char *argv[])
{
    char opt;

    char *filename = NULL,
         *archive = NULL,
         *image = NULL;

    struct ndpi_hw_struct hw;

    u_int16_t seasonal_period;

    float alpha, beta, gamma, ro;

    alpha = DEFAULT_ALPHA;
    beta = DEFAULT_BETA;
    gamma = DEFAULT_GAMMA;
    ro = DEFAULT_RO;
    seasonal_period = 0;

    while ((opt = getopt(argc, argv, "f:d:i:a:b:g:s:p:r:h")) != -1)
    {
        switch (opt)
        {
        case 'f':
            filename = optarg;
            break;
        case 'd':
            archive = optarg;
            break;
        case 'i':
            image = optarg;
            break;
        case 'a':
            alpha = atof(optarg);
            if ((alpha < 0.000001) || (alpha >= 1))
                alpha = DEFAULT_ALPHA;
            break;
        case 'b':
            beta = atof(optarg);
            if ((beta < 0.000001) || (beta >= 1))
                beta = DEFAULT_BETA;
            break;
        case 'g':
            gamma = atof(optarg);
            if ((gamma < 0.000001) || (gamma >= 1))
                gamma = DEFAULT_GAMMA;
            break;
        case 's':
            seasonal_period = atoi(optarg);
            if (seasonal_period <= 0)
            {
                help();
                exit(EXIT_FAILURE);
            }
            break;
        case 'r':
            ro = atof(optarg);
            if ((ro <= 0) || (ro >= 1))
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

    if (!filename || seasonal_period == 0)
    {
        help();
        exit(EXIT_FAILURE);
    }

    ndpi_hw_init(&hw, (seasonal_period * 2 - 1), 1, alpha, beta, gamma, ro); // 1 additive : 0 multiplicative

    if (read_csv(filename, &hw, archive, image) != 0)
        fprintf(stderr, "Error while reading file: %s\n", filename);

    ndpi_hw_free(&hw);
    return 0;
}