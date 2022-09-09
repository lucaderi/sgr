#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/data_source.h"

#define DEFAULT_ALPHA 0.8
#define DEFAULT_BETA 0.00035
#define DEFAULT_GAMMA 0.3
#define DEFAULT_RO 0.05
#define DEFAULT_ARCHIVE_NAME "weather.rrd"
#define DEFAULT_IMAGE_NAME "graph.png"

void help()
{
    printf(
        "Usage: ./bin/weather_anomaly -f <path-to-cvs-file> -s <season-period> [OPTIONS]\n\n"
        "Options: \n"
        "-v                     Verbose"
        "-f filename            Path to cvs file with data source\n"
        "-d archive             Name for rrd archive\n. Default %s"
        "-i image               Name for rrdtool graph\n. Default %s"
        "-a alpha               Set alpha parameter for Holt-Winters algorithm. Valid range 0 > .. < 1. Default %lf\n"
        "-b beta                Set beta parameter for Holt-Winters algorithm. Valid range 0 > .. < 1. Default %lf\n"
        "-g gamma               Set gamma parameter for Holt-Winters algorithm. Valid range 0 > .. < 1. Default %lf\n"
        "-r ro                  Set significance parameter for Holt-Winters algorithm. Valid range 0 > .. < 1. Default %lf\n"
        "-s seasonal_period     Set seasonal_period length for Holt-Winters algorithm.\n\n",
        DEFAULT_ARCHIVE_NAME, DEFAULT_IMAGE_NAME, DEFAULT_ALPHA, DEFAULT_BETA, DEFAULT_GAMMA, DEFAULT_RO);
}

int main(int argc, char *argv[])
{
    char opt;

    char *filename = NULL,
         *archive,
         *image;

    struct ndpi_hw_struct hw;

    int seasonal_period;
    unsigned short verbose;

    double alpha, beta, gamma, ro;

    alpha = DEFAULT_ALPHA;
    beta = DEFAULT_BETA;
    gamma = DEFAULT_GAMMA;
    ro = DEFAULT_RO;
    seasonal_period = 0;
    verbose = 0;

    archive = DEFAULT_ARCHIVE_NAME;
    image = DEFAULT_IMAGE_NAME;
    
    while ((opt = getopt(argc, argv, "f:vd:i:a:b:g:s:p:r:h")) != -1)
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
            if ((alpha < 0.00001) || (alpha >= 0.999999))
                alpha = DEFAULT_ALPHA;
            break;
        case 'b':
            beta = atof(optarg);
            if ((beta < 0.00001) || (beta >= 0.999999))
                beta = DEFAULT_BETA;
            break;
        case 'g':
            gamma = atof(optarg);
            if ((gamma < 0.00001) || (gamma >= 0.999999))
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
            if ((ro <= 0.00001) || (ro >= 1.))
                ro = DEFAULT_RO;
            break;
        case 'h':
            help();
            break;
        case 'v':
            verbose = 1;
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

    ndpi_hw_init(&hw, seasonal_period - 1, 1, alpha, beta, gamma, ro); // 1 additive : 0 multiplicative

    if (read_csv(filename, &hw, archive, image, verbose) != 0)
        fprintf(stderr, "Error while reading file: %s\n", filename);

    ndpi_hw_free(&hw);
    return 0;
}