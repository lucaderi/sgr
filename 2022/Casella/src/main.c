#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/data_source.h"

int main(int argc, char *argv[])
{
    char opt;

    char *filename = NULL;

    while ((opt = getopt(argc, argv, "f:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            filename = optarg;
            break;
        default:
            fprintf(stderr, "Unkwon command line option -%c\n", opt);
            break;
        }
    }

    if (!filename)
    {
        fprintf(stderr, "data source file required\n");
        exit(EXIT_FAILURE);
    }

    read_csv(filename);
    
    return 0;
}