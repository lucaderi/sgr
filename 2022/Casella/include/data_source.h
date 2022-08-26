#ifndef DATA_SOURCE_H
#define DATA_SOURCE_H

#include <ndpi_api.h>

int read_csv(char *csv_path, struct ndpi_hw_struct *hw, int period, char *archive, char *image);

#endif