#include "database.h"


//Creates a database named "dbname", hosted by "dbhost"
void database_creation(char * dbhost, char * dbname) {

    printf("Creation of database %s, hosted by %s\n", dbname, dbhost);
    //Query string creation
    size_t dim = 32 + strlen(dbname);
    char * query = malloc(dim);
    if (query == NULL) {
        perror("in malloc");
        exit(EXIT_FAILURE);
    }
    query = strncpy(query, "q=CREATE DATABASE ", 32);
    query = strncat(query, dbname, strlen(dbname)+1);
    dim = strlen(dbhost) + strlen("/query") + 1;
    char * f = malloc(dim);
    if (f == NULL) {
        perror("in malloc");
        exit(EXIT_FAILURE);
    }
    f = strncpy(f, dbhost, strlen(dbhost)+1);
    f = strncat(f, "/query", strlen("/query")+1);
    CURL *curl;
    CURLcode res;
    //Get a curl handle 
    curl = curl_easy_init();
    if(curl) {
        //Set the URL that is about to receive POST
        curl_easy_setopt(curl, CURLOPT_URL, f);
        //Specify the POST data 
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
        //Perform the request, res will get the return code 
        res = curl_easy_perform(curl);
        //Check for errors
        if(res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        //Cleanup 
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    free(query);
    free(f);

}


//Insert the string "str" into the dabatabase named "dbname", previously created, hosted by "dbhost",
void database_insert(char * dbhost, char * dbname, char * str) {

    size_t dim = strlen(dbhost) + strlen("/write?db=") + strlen(dbname) + 1;
    //Query string creation
    char * f = malloc(dim);
    if (f == NULL) {
        perror("in malloc");
        exit(EXIT_FAILURE);
    }
    f = strncpy(f, dbhost, strlen(dbhost)+1);
    f = strncat(f, "/write?db=", strlen("/write?db=")+1);
    f = strncat(f, dbname, strlen(dbname)+1);
    CURL *curl;
    CURLcode res;
    //Get a curl handle
    curl = curl_easy_init();
    if(curl) {
        //Set the URL that is about to receive POST
        curl_easy_setopt(curl, CURLOPT_URL, f);
        //Specify the POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str);
        //Perform the request, res will get the return code
        res = curl_easy_perform(curl);
        //Check for errors
        if(res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        //Cleanup 
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    free(f);

}


//Drop the database named "dbname" hosted by "dbhost"
void database_drop(char * dbhost, char * dbname) {

	printf("Dropping of database %s, hosted by %s\n", dbname, dbhost);
	//Query string creation
    size_t dim = 30 + strlen(dbname);
    char * query = malloc(dim);
    if (query == NULL) {
        perror("in malloc");
        exit(EXIT_FAILURE);
    }
    query = strncpy(query, "q=DROP DATABASE ", 30);
    query = strncat(query, dbname, strlen(dbname)+1);
    dim = strlen(dbhost) + strlen("/query") + 1;
    char * f = malloc(dim);
    if (f == NULL) {
        perror("in malloc");
        exit(EXIT_FAILURE);
    }
    f = strncpy(f, dbhost, strlen(dbhost)+1);
    f = strncat(f, "/query", strlen("/query")+1);
    CURL *curl;
    CURLcode res;
    //Get a curl handle
    curl = curl_easy_init();
    if(curl) {
        //Set the URL that is about to receive POST
        curl_easy_setopt(curl, CURLOPT_URL, f);
        //Specify the POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
        //Perform the request, res will get the return code
        res = curl_easy_perform(curl);
        //Check for errors
        if(res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        //Cleanup
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    free(query);
    free(f);

}