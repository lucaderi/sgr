#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char ch_host[256];
    char ch_db[64];
    char ch_table[64];
    char ch_target_url[512];
} chiba_config;

extern chiba_config global_config;
int load_config();

#endif