#ifndef DEFENSE_CONFIG_H
#define DEFENSE_CONFIG_H

#include <stdint.h>

#define DEFENSE_CONFIG_DEFAULT_PATH "config/config.yaml"
#define DEFENSE_CONFIG_PROJECT_PATH "src/defense/dhcp_starvation_detector/config/config.yaml"
#define DEFENSE_CONFIG_ENV          "DHCP_DEFENSE_CONFIG"

/*
 * Load the YAML configuration file. If path is NULL, the module first checks
 * DHCP_DEFENSE_CONFIG, then config/config.yaml in the current working
 * directory, then the project-root path under src/.
 *
 * The parser supports the project YAML subset:
 *   section:
 *     key: value
 *     subsection:
 *       key: value
 *   flat.key: value
 *
 * Returns 0 on success, -1 on error.
 */
int cfg_load(const char *path);

/* Load the default/env config only if nothing has been loaded yet. */
int cfg_load_default(void);

/*
 * Mark configuration as intentionally loaded with no file. Getters will still
 * honor environment overrides, then fall back to their compiled defaults.
 * This is intended for standalone module tests, not for the main detector.
 */
void cfg_use_defaults(const char *base_dir);

/* Return the path of the loaded config, or an empty string. */
const char *cfg_loaded_path(void);

/* Return the project base directory inferred from the loaded config path. */
const char *cfg_base_path(void);

/*
 * Typed getters. Lookup priority for each key:
 *   1. Environment variable: key converted to uppercase with '.' replaced by '_'
 *      e.g. "netconf.password" -> NETCONF_PASSWORD
 *   2. Value from the loaded config file.
 *   3. fallback, if the key is missing or the value is malformed.
 */
int      cfg_get_int(const char *key, int fallback);
uint32_t cfg_get_u32(const char *key, uint32_t fallback);
double   cfg_get_double(const char *key, double fallback);
float    cfg_get_float(const char *key, float fallback);
const char *cfg_get_string(const char *key, const char *fallback);

/*
 * Read a path-valued key and resolve relative paths against the detector
 * project root inferred from the loaded config. For example, when the config is
 * src/defense/dhcp_starvation_detector/config/config.yaml, db/whitelist.txt
 * resolves to src/defense/dhcp_starvation_detector/db/whitelist.txt.
 */
const char *cfg_resolve_path(const char *key, const char *fallback);

#endif /* DEFENSE_CONFIG_H */
