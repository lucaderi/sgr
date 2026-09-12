#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

chiba_config global_config;

 #define SET_CONFIG(dest, src) do { \
    strncpy(dest, src, sizeof(dest) - 1); \
    dest[sizeof(dest) - 1] = '\0'; \
} while(0)

int load_config() {
    /* Default configuration */
    SET_CONFIG(global_config.ch_host, "http://127.0.0.1:8123");
    SET_CONFIG(global_config.ch_db, "chiba");
    SET_CONFIG(global_config.ch_table, "ingest_flows");

    FILE *f = fopen("chiba.conf", "r");
    if (f == NULL) return -1; /* This implies default config */
    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        char key[128];
        char value[128];
        /* Parse up to 127 chars before '=' into key, 
         * and up to 127 chars before newline into value */
        if (sscanf(line, "%127[^=]=%127[^\n]", key, value) == 2) {
            if (strcmp(key, "CH_HOST") == 0) 
                SET_CONFIG(global_config.ch_host, value);
            else if (strcmp(key, "CH_DB") == 0) 
                SET_CONFIG(global_config.ch_db, value);
            else if (strcmp(key, "CH_TABLE") == 0) 
                SET_CONFIG(global_config.ch_table, value);
        }
    }
    fclose(f);

    /* Shell environment variables override file config */
    if (getenv("CH_HOST")) 
        SET_CONFIG(global_config.ch_host, getenv("CH_HOST"));
    if (getenv("CH_DB")) 
        SET_CONFIG(global_config.ch_db, getenv("CH_DB"));
    if (getenv("CH_TABLE")) 
        SET_CONFIG(global_config.ch_table, getenv("CH_TABLE"));

    /* snprintf: safe strings concatenation */
    snprintf(global_config.ch_target_url, sizeof(global_config.ch_target_url),
    "%s/?query=INSERT%%20INTO%%20%s.%s%%20FORMAT%%20RowBinary", 
    global_config.ch_host, global_config.ch_db, global_config.ch_table);

    return 0;
}
