#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>

//Creates a database named "dbname", hosted by "dbhost"
void database_creation(char * dbhost, char * dbname);

//Insert the string "str" into the dabatabase named "dbname", previously created, hosted by "dbhost",
void database_insert(char * dbhost, char * dbname, char * str);

//Drop the database named "dbname" hosted by "dbhost"
void database_drop(char * dbhost, char * dbname);