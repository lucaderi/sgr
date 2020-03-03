#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

//Struct for configuration parameters
struct configuration {
    char * address;
    char * db_address;
    char * clientid;
    char ** topics;
    int qos;
    int n_topics;
};

//Initialize the memory that will contains the configuration parameters
void configuration_initialize(struct configuration * conf);

//Clean the string from tab and line feed fonts
char * string_cleaner(char * str);

//Frees the memory occupied by the configuration parameters
void configuration_free(struct configuration * conf);

//Parses the configuration file
int configuration_parsing(struct configuration * conf, char * filename);