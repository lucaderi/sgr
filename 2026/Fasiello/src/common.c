#include "common.h"
#include "ndpi_api.h"
#include "ndpi_typedefs.h"

int init_ndpi_engine(CaptureContext *ctx) {
    ctx->ndpi_struct = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
    if (ctx->ndpi_struct == NULL) {
        return -1;
    }
    int t = ndpi_finalize_initialization(ctx->ndpi_struct);
    if (t != 0) {
        return -1;
    }
    return 0;
}

void cleanup_context(CaptureContext *ctx) {
    // cleans detection module
    if (ctx->ndpi_struct != NULL) {
        ndpi_exit_detection_module(ctx->ndpi_struct);
        ctx->ndpi_struct = NULL;
    }
    // cleans pcap handle
    if (ctx->handle != NULL) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
}

void init_config(Config *config) {
    config->pcap_file = NULL;
    config->local_ip = 0;
    config->rrd_path = strdup("test/out/netflow_metrics.rrd");
    config->threshold = 0.01;
    config->convergence = 0.001;
    config->max_flows = 100000;
    config->norm_interval_check = 1000;
}
void free_config(Config *config) {
    free(config->pcap_file);
    free(config->rrd_path);
}
