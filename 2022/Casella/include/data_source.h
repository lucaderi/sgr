#ifndef DATA_SOURCE_H
#define DATA_SOURCE_H
#include <ndpi/ndpi_api.h>

int read_csv(char *csv_path, struct ndpi_hw_struct *hw, char *archive, char *image, unsigned short verbose);
#endif