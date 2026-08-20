#include "rrd_stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../config/defense_config.h"

static uint32_t rrd_cfg_u32(const char *key, const char *legacy_key,
                            uint32_t fallback)
{
    return cfg_get_u32(key, cfg_get_u32(legacy_key, fallback));
}

static double rrd_cfg_double(const char *key, const char *legacy_key,
                             double fallback)
{
    return cfg_get_double(key, cfg_get_double(legacy_key, fallback));
}

static long long rrd_aligned_timestamp(void)
{
    static long long last_ts = 0;
    int step = (int)rrd_cfg_u32("rrd.step_secs", "detector.rrd.step_secs", 10u);
    time_t now = time(NULL);
    long long ts;

    if (step <= 0)
        step = 10;

    /* Keep GAUGE samples on RRD step boundaries so integer snapshots stay integer. */
    ts = (long long)(now - (now % step));
    if (ts <= last_ts)
        ts = last_ts + step;
    last_ts = ts;
    return ts;
}

static int shell_quote(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (dst_size < 3)
        return -1;

    dst[j++] = '\'';
    for (size_t i = 0; src[i] != '\0'; i++) {
        if (src[i] == '\'') {
            const char *esc = "'\\''";
            for (size_t k = 0; esc[k] != '\0'; k++) {
                if (j + 1 >= dst_size)
                    return -1;
                dst[j++] = esc[k];
            }
        } else {
            if (j + 1 >= dst_size)
                return -1;
            dst[j++] = src[i];
        }
    }

    if (j + 1 >= dst_size)
        return -1;
    dst[j++] = '\'';
    dst[j] = '\0';
    return 0;
}

static int rrd_schema_current(const char *path)
{
    char qpath[512];
    char cmd[768];
    char line[256];
    int found = 0;

    if (shell_quote(path, qpath, sizeof(qpath)) != 0)
        return 1;

    if (snprintf(cmd, sizeof(cmd), "rrdtool info %s 2>/dev/null", qpath) >=
        (int)sizeof(cmd))
        return 1;

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return 1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "ds[pool_tte_secs]") != NULL) {
            found = 1;
            break;
        }
    }

    if (pclose(fp) != 0)
        return 1;

    return found;
}

void rrd_init(const char *path)
{
    if (!path || !*path) {
        fprintf(stderr, "[WARN] [rrd] create skipped: empty path\n");
        return;
    }

    if (access(path, F_OK) == 0) {
        if (rrd_schema_current(path))
            return;

        char backup[512];
        if (snprintf(backup, sizeof(backup), "%s.old", path) >=
            (int)sizeof(backup)) {
            fprintf(stderr, "[WARN] [rrd] schema changed but backup path is too long\n");
            return;
        }
        if (rename(path, backup) == 0)
            printf("[rrd] schema changed: moved old database to %s\n", backup);
        else
            fprintf(stderr,
                    "[WARN] [rrd] schema changed but old database could not be moved\n");
    }

    int step = (int)rrd_cfg_u32("rrd.step_secs", "detector.rrd.step_secs", 10u);
    int heartbeat = step * (int)rrd_cfg_u32("rrd.heartbeat_multiplier",
                                            "detector.rrd.heartbeat_multiplier",
                                            2u);
    int history_hours = (int)rrd_cfg_u32("rrd.history_hours",
                                         "detector.rrd.history_hours",
                                         24u);
    int samples;
    double xff = rrd_cfg_double("rrd.xfiles_factor",
                                "detector.rrd.xfiles_factor",
                                0.5);

    if (step <= 0)
        step = 10;
    if (heartbeat <= 0)
        heartbeat = step * 2;
    if (history_hours <= 0)
        history_hours = 24;
    samples = history_hours * 3600 / step;
    if (samples <= 0)
        samples = 1;

    char qpath[512];
    char cmd[2048];

    if (shell_quote(path, qpath, sizeof(qpath)) != 0) {
        fprintf(stderr, "[WARN] [rrd] create failed: path too long\n");
        return;
    }

    if (snprintf(cmd, sizeof(cmd),
        "rrdtool create %s --step=%d "
        "DS:discovers:GAUGE:%d:0:U "
        "DS:unique_macs:GAUGE:%d:0:U "
        "DS:la_ratio:GAUGE:%d:0:1 "
        "DS:bucket_tokens:GAUGE:%d:0:U "
        "DS:bucket_capacity:GAUGE:%d:0:U "
        "DS:baseline_ema:GAUGE:%d:0:U "
        "DS:baseline_dev:GAUGE:%d:0:U "
        "DS:pool_used:GAUGE:%d:0:U "
        "DS:pool_total:GAUGE:%d:0:U "
        "DS:pool_usage_pct:GAUGE:%d:0:100 "
        "DS:pool_growth:GAUGE:%d:0:U "
        "DS:pool_tte_secs:GAUGE:%d:0:U "
        "RRA:AVERAGE:%.3f:1:%d "
        "RRA:MAX:%.3f:1:%d",
        qpath, step,
        heartbeat, heartbeat, heartbeat,
        heartbeat, heartbeat, heartbeat, heartbeat,
        heartbeat, heartbeat, heartbeat, heartbeat, heartbeat,
        xff, samples,
        xff, samples) >= (int)sizeof(cmd)) {
        fprintf(stderr, "[WARN] [rrd] create failed: command too long\n");
        return;
    }

    if (system(cmd) != 0)
        fprintf(stderr,
                "[WARN] [rrd] create failed "
                "(is rrdtool installed? sudo apt install rrdtool)\n");
    else {
        printf("[rrd] database created: %s\n", path);
        fflush(stdout);
    }
}

void rrd_update(const char *path, const rrd_sample_t *sample)
{
    char qpath[512];
    char cmd[1024];
    long long ts;

    if (!path || !*path) {
        fprintf(stderr, "[WARN] [rrd] update skipped: empty path\n");
        return;
    }

    if (!sample) {
        fprintf(stderr, "[WARN] [rrd] update skipped: NULL sample\n");
        return;
    }

    if (shell_quote(path, qpath, sizeof(qpath)) != 0) {
        fprintf(stderr, "[WARN] [rrd] update failed: path too long\n");
        return;
    }

    ts = rrd_aligned_timestamp();

    if (snprintf(cmd, sizeof(cmd),
        "rrdtool update %s "
        "%lld:%u:%u:%.4f:%.4f:%.4f:%.4f:%.4f:%u:%u:%.4f:%u:%u",
        qpath,
        ts,
        sample->discovers,
        sample->unique_macs,
        sample->la_ratio,
        sample->bucket_tokens,
        sample->bucket_capacity,
        sample->baseline_ema,
        sample->baseline_dev,
        sample->pool_used,
        sample->pool_total,
        sample->pool_usage_pct,
        sample->pool_growth,
        sample->pool_tte_secs) >= (int)sizeof(cmd)) {
        fprintf(stderr, "[WARN] [rrd] update failed: command too long\n");
        return;
    }

    if (system(cmd) != 0)
        fprintf(stderr, "[WARN] [rrd] update failed\n");
    else {
        printf("[rrd] updated  discovers=%-5u  unique=%-5u  la=%.2f"
               "  bucket=%.0f/%.0f  baseline=%.1f+-%.1f"
               "  pool=%u/%u %.0f%% growth=%u tte=%us\n",
               sample->discovers,
               sample->unique_macs,
               sample->la_ratio,
               sample->bucket_tokens,
               sample->bucket_capacity,
               sample->baseline_ema,
               sample->baseline_dev,
               sample->pool_used,
               sample->pool_total,
               sample->pool_usage_pct,
               sample->pool_growth,
               sample->pool_tte_secs);
        fflush(stdout);
    }
}
