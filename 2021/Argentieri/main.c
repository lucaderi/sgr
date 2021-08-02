#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <rrd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <math.h>
#include <argp.h>

#include "array_list.h"


// struttura contenente la configurazione specificata da riga di comando
struct arguments {
    unsigned long start, end;
    int rra;
    char *filename;
    bool verbose;
} pargs = {0};


// printf se l'utente ha specificato -v o --verbose
int verbose_log(const char *restrict format, ...) {
    if (!pargs.verbose)
        return 0;

    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);

    return ret;
}


// struttura che rappresenta una misurazione della serie temporale
struct ts_row {
    unsigned long timestamp;
    double value;
};

// struttura per la statistica
struct ts_stats {
    struct {
        unsigned long start, end;
    } learning_params;

    double mean;
    double sigma;

    struct {
        double sigma1_min, sigma1_max;
        double sigma2_min, sigma2_max;
        double sigma3_min, sigma3_max;
    } bounds;
};

// rappresenta una anomalia
struct anomaly {
    // timestamp di inizio e fine
    unsigned long start, end;
    // tipo di anomalia
    enum {
        SIGMA1, SIGMA2, SIGMA3, OUTLIER
    } type;
    // statistiche anomalia (media)
    struct {
        unsigned int num_values;
        double sum;
    } stats;
};

void print_anomaly(struct anomaly *an) {
    if (an->type == OUTLIER)
        printf("Outliers detected from %lu to %lu (%d consecutive readings outside sigma3 and mean %f)\n",
               an->start, an->end, an->stats.num_values, (an->stats.sum / an->stats.num_values));
    else
        printf("Anomaly from %lu to %lu (%d consecutive readings inside sigma%d and mean %f)\n",
               an->start, an->end, an->stats.num_values, an->type + 1, (an->stats.sum / an->stats.num_values));
}

void print_anomalies(ArrayList *list) {
    for (int i = 0; i < list->length; i++) {
        struct anomaly *an = array_list_get(list, i);
        print_anomaly(an);
    }
}


void stats_init(struct ts_stats *tsStats, unsigned long start, unsigned long end) {
    memset(tsStats, 0, sizeof(struct ts_stats));
    tsStats->learning_params.start = start;
    tsStats->learning_params.end = end;
}

// procedura aprrendimento
void stats_learn(struct ts_stats *tsStats, ArrayList *rows) {
    if (rows->length < 10)
        fprintf(stderr, "Warning: too few measurements to learn from!\n");
    double sum = 0;
    double sum_square = 0;
    for (int i = 0; i < rows->length; i++) {
        struct ts_row *row = array_list_get(rows, i);
        sum += row->value;
        sum_square += row->value * row->value;
    }
    tsStats->mean = sum / rows->length;

    double sq_diff_sum = 0;
    for (int i = 0; i < rows->length; i++) {
        struct ts_row *row = array_list_get(rows, i);
        double diff = row->value - tsStats->mean;
        sq_diff_sum += diff * diff;
    }
    double variance = sq_diff_sum / rows->length;
    tsStats->sigma = sqrt(variance);

    tsStats->bounds.sigma3_min = tsStats->mean - 3 * tsStats->sigma;
    tsStats->bounds.sigma3_max = tsStats->mean + 3 * tsStats->sigma;
    tsStats->bounds.sigma2_min = tsStats->mean - 2 * tsStats->sigma;
    tsStats->bounds.sigma2_max = tsStats->mean + 2 * tsStats->sigma;
    tsStats->bounds.sigma1_min = tsStats->mean - 1 * tsStats->sigma;
    tsStats->bounds.sigma1_max = tsStats->mean + 1 * tsStats->sigma;

    verbose_log("Learning done: mean %f sigma %f\n", tsStats->mean, tsStats->sigma);
}


// procedura individuazione anomalie
struct anomaly *detect_anomaly(struct ts_stats *tsStats, const struct ts_row row, struct anomaly *an) {
    struct anomaly old;
    memcpy(&old, an, sizeof(struct anomaly));

    if (tsStats->bounds.sigma1_min < row.value && row.value < tsStats->bounds.sigma1_max) {
        an->type = SIGMA1;
    } else if (tsStats->bounds.sigma2_min < row.value && row.value < tsStats->bounds.sigma2_max) {
        an->type = SIGMA2;
    } else if (tsStats->bounds.sigma3_min < row.value && row.value < tsStats->bounds.sigma3_max) {
        an->type = SIGMA3;
    } else if (row.value < tsStats->bounds.sigma3_min || row.value > tsStats->bounds.sigma3_max) {
        an->type = OUTLIER;
    }

    if (old.type != an->type) {
        an->stats.num_values = 0;
        an->stats.sum = 0;
    }
    an->stats.num_values++;
    an->stats.sum += row.value;

    if (an->type == OUTLIER) {
        // outliers detected!
        if (an->start == 0) {
            verbose_log("Anomaly: outlier detected at %lu\n", row.timestamp);
            an->start = row.timestamp;
        }
    } else if (an->type == SIGMA1 && an->stats.num_values > 50) {
        if (an->start == 0) {
            verbose_log("Anomaly: sigma1 detected at %lu\n", row.timestamp);
            an->start = row.timestamp;
        }
    } else if (an->type == SIGMA2 && an->stats.num_values > 15) {
        if (an->start == 0) {
            verbose_log("Anomaly: sigma2 detected at %lu\n", row.timestamp);
            an->start = row.timestamp;
        }
    } else if (an->type == SIGMA3 && an->stats.num_values > 6) {
        if (an->start == 0) {
            verbose_log("Anomaly: sigma3 detected at %lu\n", row.timestamp);
            an->start = row.timestamp;
        }
    } else {
        if (an->start > 0) {
            old.end = row.timestamp;
            an->start = 0;
            struct anomaly *new = malloc(sizeof(struct anomaly));
            memcpy(new, &old, sizeof(struct anomaly));
            return new;
        }
    }
    return NULL;
}

ArrayList detect_anomalies(struct ts_stats *tsStats, ArrayList *rows) {
    ArrayList anomalies;
    array_list_init(&anomalies);

    struct anomaly an = {0};
    for (int i = 0; i < rows->length; i++) {
        struct ts_row *row = array_list_get(rows, i);
        struct anomaly *anomaly = detect_anomaly(tsStats, *row, &an);
        if (anomaly != NULL) {
            array_list_add(&anomalies, anomaly);
            if (pargs.verbose)
                print_anomaly(anomaly);
        }
    }
    return anomalies;
}

// ad ogni chiamata restituisce la prossima riga, NULL se non ce ne sono altre
struct ts_row database_iterator(xmlNodePtr *iter) {
    struct ts_row row = {0};
    xmlNodePtr cur_node = *iter;
    while ((row.timestamp == 0 || row.value == 0) && cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && strcmp((char *) cur_node->name, "row") == 0) {
            xmlNode *value_node = cur_node->children;
            if (row.value == 0 && strcmp("v", (char *) value_node->name) == 0)
                row.value = strtod((char *) value_node->children->content, NULL);
        } else if (cur_node->type == XML_COMMENT_NODE) {
            if (row.timestamp == 0) {
                char *comment = (char *) cur_node->content;
                char *after_slash = index(comment, '/') + 1;
                row.timestamp = strtoul(after_slash, NULL, 10);
            }
        }
        cur_node = cur_node->next;
    }
    *iter = cur_node;
    return row;
}

// restituisce una lista contente tutte le righe su cui effettuare l'apprendimento
ArrayList get_learning_rows(xmlNodePtr dbnode, struct ts_stats *tsStats) {
    xmlNodePtr iter = dbnode->children;
    ArrayList list;
    array_list_init(&list);
    for (struct ts_row row = database_iterator(&iter); iter != NULL; row = database_iterator(&iter)) {
        if (row.timestamp < tsStats->learning_params.start)
            continue;
        if (row.timestamp > tsStats->learning_params.end)
            break;
        array_list_copy_add(&list, &row, sizeof(struct ts_row));
    }
    return list;
}

ArrayList get_detection_rows(xmlNodePtr dbnode, struct ts_stats *tsStats) {
    xmlNodePtr iter = dbnode->children;
    ArrayList list;
    array_list_init(&list);
    for (struct ts_row row = database_iterator(&iter); iter != NULL; row = database_iterator(&iter)) {
        if (row.timestamp > tsStats->learning_params.end)
            array_list_copy_add(&list, &row, sizeof(struct ts_row));
    }
    return list;
}

// restituisce la parte di XML che si trova dentro a <database></database>
xmlNodePtr get_database_node(xmlDocPtr doc, int rra) {
    xmlChar xpathExpr[30];
    snprintf((char *) xpathExpr, 30, "/rrd/rra[%d]/database", rra + 1);
    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        fprintf(stderr, "Error: unable to create new XPath context\n");
        return NULL;
    }
    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if (xpathObj == NULL) {
        fprintf(stderr, "Error: unable to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx);
        return NULL;
    }

    if (xpathObj->nodesetval == NULL) {
        fprintf(stderr, "Error: xpath expression returned no nodes.\n");
        xmlXPathFreeObject(xpathObj);
        xmlXPathFreeContext(xpathCtx);
        return NULL;
    }

    xmlNodePtr result = *xpathObj->nodesetval->nodeTab;

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);

    return result;
}

// passa l'output del dump al parser XML
size_t parse_callback(const void *data, size_t len, void *user) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) user;
    if (xmlParseChunk(ctxt, data, (int) len, 0) != 0) {
        fprintf(stderr, "Failed to parse RRD file!\n");
        return 0;
    }
    return len;
}

// restituisce il documento XML parsato
xmlDocPtr rrd_to_xmlDoc(char *filename) {
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, filename);
    xmlDocPtr doc;

    int r = rrd_dump_cb_r(filename, 0, parse_callback, ctxt);
    if (r < 0) {
        fprintf(stderr, "rrd_dump_cb_r error %d\n", r);
        return NULL;
    }

    r = xmlParseChunk(ctxt, NULL, 0, 1);
    if (r != 0) {
        fprintf(stderr, "Failed to parse XML output from rrd_dump: xmlParseChunk returned %d\n", r);
        return NULL;
    }

    doc = ctxt->myDoc;
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();
    return doc;
}

const char *argp_program_version = "anomalydetect 0.1";
const char *argp_program_bug_address = "Elia Argentieri <elia@elinvention.ovh>";
static char doc[] = "Detects outliers and anomalies in RRD files.";
static char args_doc[] = "-s START -e END FILENAME";
static struct argp_option options[] = {
        {"start", 's',   "start", 0, "Learning start timestamp."},
        {"end", 'e',     "end",   0, "Learning end timestamp."},
        {"rra", 'r',     "RRA",   0, "Which RRA database to scan."},
        {"verbose", 'v', 0,       0, "Print debug information."},
        {0}
};


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 's':
            arguments->start = strtoul(arg, NULL, 10);
            break;
        case 'e':
            arguments->end = strtoul(arg, NULL, 10);
            break;
        case 'r':
            arguments->rra = atoi(arg);
            break;
        case 'v':
            arguments->verbose = true;
        case ARGP_KEY_ARG:
            arguments->filename = arg;
            return 0;
        case ARGP_KEY_END:
            if (arguments->filename == NULL || arguments->start == 0 || arguments->end == 0)
                argp_failure(state, 1, 0, "missing required arguments.");
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char *argv[]) {
    argp_parse(&argp, argc, argv, 0, 0, &pargs);

    verbose_log("Parsing %s...\n", pargs.filename);
    xmlDocPtr xml_doc = rrd_to_xmlDoc(pargs.filename);
    if (xml_doc == NULL)
        return -1;

    verbose_log("Filterning xml tree...\n");
    xmlNodePtr dbnode = get_database_node(xml_doc, pargs.rra);
    if (dbnode == NULL) {
        xmlFreeDoc(xml_doc);
        return -2;
    }


    {
        struct ts_stats tsStats;
        stats_init(&tsStats, pargs.start, pargs.end);

        {
            verbose_log("Learning...\n");
            ArrayList rows = get_learning_rows(dbnode, &tsStats);
            stats_learn(&tsStats, &rows);
            array_list_free(&rows);
        }

        {
            verbose_log("Detecting anomalies...\n");
            ArrayList rows = get_detection_rows(dbnode, &tsStats);
            ArrayList anomalies = detect_anomalies(&tsStats, &rows);
            verbose_log("Anomalies detected:\n");
            print_anomalies(&anomalies);
            array_list_free(&anomalies);
            array_list_free(&rows);
        }

    }

    xmlFreeDoc(xml_doc);
    return 0;
}
