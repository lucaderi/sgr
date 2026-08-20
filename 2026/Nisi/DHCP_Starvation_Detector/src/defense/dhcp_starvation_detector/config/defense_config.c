#include "defense_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFG_MAX_ENTRIES 256
#define CFG_KEY_LEN     96
#define CFG_VALUE_LEN   256
#define CFG_SECTION_LEN 64

typedef struct {
    char key[CFG_KEY_LEN];
    char value[CFG_VALUE_LEN];
} cfg_entry_t;

static cfg_entry_t entries[CFG_MAX_ENTRIES];
static int entry_count = 0;
static int loaded = 0;
static int default_load_failed = 0;
static char loaded_path[CFG_VALUE_LEN];
static char base_path[CFG_VALUE_LEN] = ".";
static char warned_invalid_keys[CFG_MAX_ENTRIES][CFG_KEY_LEN];
static int warned_invalid_count = 0;

static int path_is_abs(const char *path)
{
    return path && path[0] == '/';
}

static void path_parent(const char *path, char *buf, size_t size)
{
    const char *slash;
    size_t len;

    if (!buf || size == 0)
        return;

    if (!path || !*path) {
        snprintf(buf, size, ".");
        return;
    }

    slash = strrchr(path, '/');
    if (!slash) {
        snprintf(buf, size, ".");
        return;
    }
    if (slash == path) {
        snprintf(buf, size, "/");
        return;
    }

    len = (size_t)(slash - path);
    if (len >= size)
        len = size - 1;
    memcpy(buf, path, len);
    buf[len] = '\0';
}

static const char *path_leaf(const char *path)
{
    const char *slash;

    if (!path)
        return "";
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void set_loaded_paths(const char *selected)
{
    char config_dir[CFG_VALUE_LEN];
    int n;

    n = snprintf(loaded_path, sizeof(loaded_path), "%s", selected);
    if (n < 0 || (size_t)n >= sizeof(loaded_path)) {
        fprintf(stderr, "[WARN] config: loaded path truncated: %s\n", selected);
        loaded_path[sizeof(loaded_path) - 1] = '\0';
    }

    path_parent(selected, config_dir, sizeof(config_dir));
    if (strcmp(path_leaf(config_dir), "config") == 0)
        path_parent(config_dir, base_path, sizeof(base_path));
    else
        snprintf(base_path, sizeof(base_path), "%s", config_dir);

    if (base_path[0] == '\0')
        snprintf(base_path, sizeof(base_path), ".");
}

static void warn_invalid_once(const char *key, const char *value,
                              const char *type)
{
    for (int i = 0; i < warned_invalid_count; i++)
        if (strcmp(warned_invalid_keys[i], key) == 0)
            return;

    if (warned_invalid_count < CFG_MAX_ENTRIES) {
        snprintf(warned_invalid_keys[warned_invalid_count],
                 sizeof(warned_invalid_keys[warned_invalid_count]),
                 "%s", key);
        warned_invalid_count++;
    }

    fprintf(stderr,
            "[WARN] config: invalid %s value for %s='%s'; using fallback\n",
            type, key, value ? value : "");
}

static char *trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1)))
        end--;
    *end = '\0';

    return s;
}

static void strip_comment(char *s)
{
    int quote = 0;

    for (; *s; s++) {
        if (*s == '"' || *s == '\'') {
            if (quote == 0)
                quote = *s;
            else if (quote == *s)
                quote = 0;
        }

        if (*s == '#' && quote == 0) {
            *s = '\0';
            return;
        }
    }
}

static void unquote(char *s)
{
    size_t len = strlen(s);

    if (len < 2)
        return;

    if ((s[0] == '"' && s[len - 1] == '"') ||
        (s[0] == '\'' && s[len - 1] == '\'')) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static int store_value(const char *key, const char *value)
{
    if (strlen(key) >= CFG_KEY_LEN) {
        fprintf(stderr, "[FAIL] config: key too long: %s\n", key);
        return -1;
    }
    if (strlen(value) >= CFG_VALUE_LEN) {
        fprintf(stderr, "[FAIL] config: value too long for key %s\n", key);
        return -1;
    }

    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].key, key) == 0) {
            snprintf(entries[i].value, sizeof(entries[i].value), "%s", value);
            return 0;
        }
    }

    if (entry_count >= CFG_MAX_ENTRIES) {
        fprintf(stderr, "[FAIL] config: too many entries, max=%d\n", CFG_MAX_ENTRIES);
        return -1;
    }

    snprintf(entries[entry_count].key, sizeof(entries[entry_count].key),
             "%s", key);
    snprintf(entries[entry_count].value, sizeof(entries[entry_count].value),
             "%s", value);
    entry_count++;
    return 0;
}

int cfg_load(const char *path)
{
    const char *selected = path;
    FILE *fp;
    char line[512];
    char section[CFG_SECTION_LEN] = "";
    char subsection[CFG_SECTION_LEN] = "";
    int sub_indent = -1;
    int line_no = 0;

    if (!selected || !*selected) {
        selected = getenv(DEFENSE_CONFIG_ENV);
        if (!selected || !*selected) {
            selected = DEFENSE_CONFIG_DEFAULT_PATH;
            fp = fopen(selected, "r");
            if (!fp) {
                selected = DEFENSE_CONFIG_PROJECT_PATH;
                fp = fopen(selected, "r");
            }
        } else {
            fp = fopen(selected, "r");
        }
    } else {
        fp = fopen(selected, "r");
    }

    if (!fp) {
        fprintf(stderr, "[FAIL] config: unable to open %s: %s\n",
                selected, strerror(errno));
        return -1;
    }

    entry_count = 0;
    warned_invalid_count = 0;
    default_load_failed = 0;
    memset(entries, 0, sizeof(entries));
    memset(warned_invalid_keys, 0, sizeof(warned_invalid_keys));

    while (fgets(line, sizeof(line), fp)) {
        char *p;
        char *colon;
        char *key;
        char *value;
        int has_value;
        int indent = 0;

        line_no++;
        strip_comment(line);

        p = line;
        while (*p == ' ' || *p == '\t') {
            indent++;
            p++;
        }

        p = trim(p);
        if (*p == '\0')
            continue;

        colon = strchr(p, ':');
        if (!colon) {
            fprintf(stderr, "[FAIL] config: %s:%d: missing ':'\n",
                    selected, line_no);
            fclose(fp);
            return -1;
        }

        *colon = '\0';
        key = trim(p);
        value = trim(colon + 1);
        has_value = (*value != '\0');
        unquote(value);

        if (!has_value) {
            if (indent == 0) {
                if (snprintf(section, sizeof(section), "%s", key) >=
                    (int)sizeof(section)) {
                    fprintf(stderr, "[FAIL] config: %s:%d: section name too long\n",
                            selected, line_no);
                    fclose(fp);
                    return -1;
                }
                subsection[0] = '\0';
                sub_indent = -1;
            } else {
                if (snprintf(subsection, sizeof(subsection), "%s", key) >=
                    (int)sizeof(subsection)) {
                    fprintf(stderr, "[FAIL] config: %s:%d: subsection name too long\n",
                            selected, line_no);
                    fclose(fp);
                    return -1;
                }
                sub_indent = indent;
            }
            continue;
        }

        char full_key[CFG_KEY_LEN];
        int key_len;
        if (indent == 0) {
            key_len = snprintf(full_key, sizeof(full_key), "%s", key);
        } else if (sub_indent >= 0 && indent > sub_indent &&
                   section[0] != '\0' && subsection[0] != '\0') {
            key_len = snprintf(full_key, sizeof(full_key), "%s.%s.%s",
                               section, subsection, key);
        } else {
            if (section[0] != '\0')
                key_len = snprintf(full_key, sizeof(full_key), "%s.%s",
                                   section, key);
            else
                key_len = snprintf(full_key, sizeof(full_key), "%s", key);
            subsection[0] = '\0';
            sub_indent = -1;
        }
        if (key_len < 0 || (size_t)key_len >= sizeof(full_key)) {
            fprintf(stderr, "[FAIL] config: %s:%d: key too long\n",
                    selected, line_no);
            fclose(fp);
            return -1;
        }

        if (store_value(full_key, value) != 0) {
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "[FAIL] config: read error while parsing %s\n", selected);
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "[FAIL] config: fclose %s: %s\n",
                selected, strerror(errno));
        return -1;
    }
    loaded = 1;
    set_loaded_paths(selected);
    return 0;
}

int cfg_load_default(void)
{
    if (loaded)
        return 0;
    if (default_load_failed)
        return -1;

    if (cfg_load(NULL) != 0) {
        default_load_failed = 1;
        return -1;
    }

    return 0;
}

void cfg_use_defaults(const char *base_dir)
{
    entry_count = 0;
    warned_invalid_count = 0;
    default_load_failed = 0;
    memset(entries, 0, sizeof(entries));
    memset(warned_invalid_keys, 0, sizeof(warned_invalid_keys));
    loaded = 1;
    snprintf(loaded_path, sizeof(loaded_path), "<compiled-defaults>");
    snprintf(base_path, sizeof(base_path), "%s",
             base_dir && *base_dir ? base_dir : ".");
}

const char *cfg_loaded_path(void)
{
    return loaded ? loaded_path : "";
}

const char *cfg_base_path(void)
{
    if (!loaded)
        (void)cfg_load_default();
    return base_path;
}

static void key_to_env(const char *key, char *buf, size_t size)
{
    size_t i;
    for (i = 0; i < size - 1 && key[i]; i++)
        buf[i] = (key[i] == '.') ? '_' : toupper((unsigned char)key[i]);
    buf[i] = '\0';
}

static const char *lookup(const char *key)
{
    char env_name[CFG_KEY_LEN];
    const char *env_val;

    key_to_env(key, env_name, sizeof(env_name));
    env_val = getenv(env_name);
    if (env_val)
        return env_val;

    if (!loaded)
        (void)cfg_load_default();

    for (int i = 0; i < entry_count; i++)
        if (strcmp(entries[i].key, key) == 0)
            return entries[i].value;

    return NULL;
}

int cfg_get_int(const char *key, int fallback)
{
    const char *v = lookup(key);
    char *end = NULL;
    long n;

    if (!v)
        return fallback;

    errno = 0;
    n = strtol(v, &end, 10);
    if (errno || end == v || *end != '\0') {
        warn_invalid_once(key, v, "integer");
        return fallback;
    }

    return (int)n;
}

uint32_t cfg_get_u32(const char *key, uint32_t fallback)
{
    const char *v = lookup(key);
    char *end = NULL;
    unsigned long n;

    if (!v)
        return fallback;

    errno = 0;
    n = strtoul(v, &end, 10);
    if (errno || end == v || *end != '\0' || n > UINT32_MAX) {
        warn_invalid_once(key, v, "unsigned integer");
        return fallback;
    }

    return (uint32_t)n;
}

double cfg_get_double(const char *key, double fallback)
{
    const char *v = lookup(key);
    char *end = NULL;
    double n;

    if (!v)
        return fallback;

    errno = 0;
    n = strtod(v, &end);
    if (errno || end == v || *end != '\0') {
        warn_invalid_once(key, v, "floating-point");
        return fallback;
    }

    return n;
}

float cfg_get_float(const char *key, float fallback)
{
    return (float)cfg_get_double(key, (double)fallback);
}

const char *cfg_get_string(const char *key, const char *fallback)
{
    const char *v = lookup(key);

    return v ? v : fallback;
}

const char *cfg_resolve_path(const char *key, const char *fallback)
{
    static char resolved[CFG_VALUE_LEN * 2];
    const char *path = cfg_get_string(key, fallback);
    const char *fallback_path = fallback ? fallback : "";
    const char *base;

    if (!path || !*path)
        return path;

    if (path_is_abs(path))
        return path;

    base = cfg_base_path();
    if (!base || !*base || strcmp(base, ".") == 0) {
        if (snprintf(resolved, sizeof(resolved), "%s", path) >=
            (int)sizeof(resolved)) {
            fprintf(stderr,
                    "[WARN] config: resolved path too long for %s; "
                    "using fallback path\n",
                    key);
            snprintf(resolved, sizeof(resolved), "%s", fallback_path);
        }
    } else {
        if (snprintf(resolved, sizeof(resolved), "%s/%s", base, path) >=
            (int)sizeof(resolved)) {
            fprintf(stderr,
                    "[WARN] config: resolved path too long for %s; "
                    "using fallback path\n",
                    key);
            snprintf(resolved, sizeof(resolved), "%s", fallback_path);
        }
    }

    return resolved;
}
