/*
 * Questo tool permette di individuare dispositivi di rete esposti su Internet attraverso Shodan e di raccogliere,
 * tramite SNMP, informazioni sul traffico delle loro interfacce di rete.
 * Una volta stabilita la connessione con il dispositivo, il sistema interroga gli OID SNMP più rilevanti
 * (come quelli relativi al traffico in ingresso e in uscita per ogni porta) e struttura i dati raccolti per l’analisi.
 * L’obiettivo principale è confrontare i pattern di traffico tra le varie interfacce utilizzando un algoritmo di similarità.
 * In questo modo, è possibile identificare coppie o gruppi di porte che mostrano comportamenti simili nel tempo.
 * Infine, il tool genera un report che descrive i risultati dell’analisi, evidenziando le interfacce più simili tra loro.
 *
 * Progetto GR 24/25 made by Luca Ferrante
*/
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "rrd.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include "utils/macros.h"
#include "ndpi_api.h"
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <math.h>

#define RRD_FILES "rrds"
#define MAX_NUM_RRDS 8192
#define DEFAULT_STEP 60
#define DEFAULT_THRESHOLD 100
#define BUF_LENGTH 512
#define DEFAULT_AGENT "127.0.0.1"
#define DEFAULT_COMMUNITY "public"
#define SNMP_INIT "snmp_manager"
#define DEFAULT_START "now-1d"
#define DEFAULT_END "now"


typedef struct {
    char* path;
    float average, stddev;
    struct ndpi_bin b;
} rrd_file_stats;

typedef struct{
    u_int step;
    u_int nIf;
    char *base_dir;
    struct snmp_session *ss;
    rrd_file_stats *rrds;
}agent_info;

volatile sig_atomic_t keep_running = 1;
u_int verbose = 0, skip_zero = 0, similarity_threshold = DEFAULT_THRESHOLD;

/* *************************************************** */

void analyze_rrd(rrd_file_stats *rrd, time_t start, time_t end) {
    unsigned long  step = 0, ds_cnt = 0;
    rrd_value_t *data, *p;
    char **names;
    time_t t;
    u_int i, num_points;
    struct ndpi_analyze_struct *s;

    if(rrd_fetch_r(rrd->path, "AVERAGE", &start, &end, &step, &ds_cnt, &names, &data) != 0) {
        printf("Unable to extract data from rrd %s\n", rrd->path);
        return;
    }

    p = data;
    num_points = (end-start)/step;

    if((s = ndpi_alloc_data_analysis(num_points)) == NULL)
        return;

    ndpi_init_bin(&rrd->b, ndpi_bin_family32, num_points);

    /* Step 1 - Compute average and stddev */
    for(t=start+1, i=0; t<end; t+=step, i++) {
        double value = (double)*p++;

        if(isnan(value)) value = 0;
        ndpi_data_add_value(s, value);
        ndpi_set_bin(&rrd->b, i, value);
    }

    rrd->average = ndpi_data_average(s);
    rrd->stddev  = ndpi_data_stddev(s);

    /* Step 2 - Bin analysis */
    ndpi_free_data_analysis(s, 1);
    rrd_freemem(data);
}

/* *************************************************** */

int circles_touch(int x1, int r1, int x2, int r2) {
    int radius_sum = r1+r2;
    int x_diff     = abs(x1 - x2);

    return((radius_sum < x_diff) ? 0 : 1);
}


/* *************************************************** */

void find_rrd_similarities(rrd_file_stats *rrd, u_int num_rrds) {
    u_int i, j, num_similar_rrds = 0, num_potentially_zero_equal = 0;

    for(i=0; i<num_rrds; i++) {
        for(j=i+1; j<num_rrds; j++) {
            /*
          Average is the circle center, and stddev is the radius
          if circles touch each other then there is a chance that
          the two rrds are similar
            */
            //printf("%d : %d => %d\n", i, j, circles_touch(rrd[i].average, rrd[i].stddev, rrd[j].average, rrd[j].stddev));

            if((rrd[i].average == 0) && (rrd[i].average == rrd[j].average)) {
                if(!skip_zero)
                    printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are alike\n",
                           rrd[i].path, rrd[i].average, rrd[i].stddev,
                           rrd[j].path, rrd[j].average, rrd[j].stddev);

                num_potentially_zero_equal++;
            } else if(circles_touch(rrd[i].average, rrd[i].stddev, rrd[j].average, rrd[j].stddev)
                    ) {
                float similarity = ndpi_bin_similarity(&rrd[i].b, &rrd[j].b, 0, similarity_threshold);
                //printf("%d : %d sono nell'if della similarità // coefficiente = %0.1f\n", i, j, similarity);
                if((similarity >= 0) && (similarity < similarity_threshold)) {
                    if(verbose)
                        printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are %s [%.1f]\n",
                               rrd[i].path, rrd[i].average, rrd[i].stddev,
                               rrd[j].path, rrd[j].average, rrd[j].stddev,
                               (similarity == 0) ? "alike" : "similar",
                               similarity
                        );

                    num_similar_rrds++;
                }
            }
        }
    }

    printf("Found %u (%.3f %%) similar RRDs / %u zero alike RRDs [num_rrds: %u]\n",
           num_similar_rrds,
           (num_similar_rrds*100.)/(float)(num_rrds*num_rrds),
           num_potentially_zero_equal,
           num_rrds);
}

/* *************************************************** */

int endsWith(const char *str, const char *suffix) {
    if (!str || !suffix)
        return false;

    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);

    if (len_suffix > len_str)
        return false;

    return strcmp(str + len_str - len_suffix, suffix) == 0;
}

void find_rrds(char *basedir, rrd_file_stats *rrds, u_int *num_rrds) {
    struct dirent **namelist;
    int n = scandir(basedir, &namelist, 0, NULL);

    if(n < 0)
        return; /* End of the tree */

    while(n--) {
        if(namelist[n]->d_name[0] != '.') {
            char path[PATH_MAX];
            struct stat s;

            ndpi_snprintf(path, sizeof(path), "%s%s", basedir, namelist[n]->d_name);

            if(stat(path, &s) == 0) {
                if(S_ISREG(s.st_mode) && endsWith(namelist[n]->d_name, ".rrd")){
                    if(*num_rrds < MAX_NUM_RRDS) {
                        rrds[*num_rrds].path = strdup(path);
                        if(rrds[*num_rrds].path != NULL)
                            (*num_rrds)++;
                    }
                }
            }
        }

        free(namelist[n]);
    }

    free(namelist);
}

/* *************************************************** */

void handle_sigint(int sig) {
    keep_running = 0;
    printf("\n[INFO] Caught SIGNAL, terminating gracefully...\n");
}

/* *************************************************** */

void init_session(struct snmp_session **ss, char* agent, char* community){
    struct snmp_session session;
    init_snmp(SNMP_INIT);
    netsnmp_init_mib();
    snmp_sess_init(&session);
    session.peername = strdup(agent);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)community;
    session.community_len = strlen((char *)session.community);
    *ss = snmp_open(&session);
    if(!*ss){
        printf("error snmp_open");
        exit(1);
    }
}

/* *************************************************** */

int getNumIf(struct snmp_session *ss){
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    int status;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    if (!read_objid("1.3.6.1.2.1.2.1.0", anOID, &anOID_len)) { //ifNumber del gruppo interface
        snmp_perror("read_objid");
        exit(1);
    }
    snmp_add_null_var(pdu, anOID, anOID_len);
    status = snmp_synch_response(ss, pdu, &response);
    if(status == STAT_SUCCESS && response->errstat==SNMP_ERR_NOERROR){
        return (int)*(response->variables->val.integer);
    }
    if (response) snmp_free_pdu(response);
}

/* *************************************************** */

void getIfOutBytes(struct snmp_session *ss, u_int nIf, unsigned int* ifOutB, int* snmp_ack){
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    int status;
    struct variable_list *vars;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    if (!read_objid("1.3.6.1.2.1.2.2.1.16", anOID, &anOID_len)) { //ifOutOctets
        snmp_perror("read_objid");
        exit(1);
    }
    pdu->non_repeaters = 0;      // numero di OID iniziali da recuperare solo una volta
    pdu->max_repetitions = nIf;   // quante "ripetizioni" vuoi ricevere per gli altri OID
    snmp_add_null_var(pdu, anOID, anOID_len);

    status = snmp_synch_response(ss, pdu, &response);
    if (status != STAT_SUCCESS) {
        if (status == STAT_TIMEOUT) {
            printf("[ERROR] Timeout contattando host %s\n", ss->peername);
        } else if (status == STAT_ERROR) {
            printf("[ERROR] Errore SNMP generico\n");
        } else {
            printf("[ERROR] Stato SNMP sconosciuto: %d\n", status);
        }
    }

    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        int i;
        for(vars = response->variables,i=0; vars; vars = vars->next_variable, i++){
            ifOutB[i] = (unsigned int)*vars->val.integer;
        }

    } else {
        printf("SNMP error\n");
        *snmp_ack = 1;
    }
    if (response) snmp_free_pdu(response);
}

/* *************************************************** */

void init_rrd(char* name, u_int step, u_int nIf, agent_info *info){
    int argc=6;
    char **argv = malloc((argc)*sizeof(char*));
    if(mkdir(name, 0755) == 0)
        printf("Creating folder for this hostname... \n");
    char buffer[BUF_LENGTH];
    int count = 0;
    while(count != nIf){
        //argv[0] lo skippa
        snprintf(buffer, sizeof(buffer), "%s/%d.rrd",name, count+1);
        info->rrds[count].path = strdup(buffer);
        argv[1]= strdup(buffer);
        argv[2]="--step";
        snprintf(buffer, sizeof(buffer), "%d", step);
        argv[3]=strdup(buffer);
        snprintf(buffer,sizeof(buffer), "DS:bytes_out_if%d:COUNTER:600:0:U", count);
        argv[4]=strdup(buffer);
        argv[5]="RRA:AVERAGE:0.5:1:576";
        SYSCZ(rrd_create(argc, argv), "Error creating rrds");
        count++;
    }

    free(argv);
}

/* *************************************************** */

void update_rrd(char *name, u_int nIf, const unsigned int *ifOutB){
    time_t timestamp = time(NULL);
    int argc=3;
    char **argv = malloc((argc)*sizeof(char*));
    char buffer[BUF_LENGTH];
    int count = 0;

    while(count != nIf){
        //argv[0] lo skippa
        snprintf(buffer, sizeof(buffer), "%s/%d.rrd",name, count+1);
        argv[1]= strdup(buffer);
        snprintf(buffer,sizeof(buffer), "%ld:%u", timestamp, ifOutB[count]);
        argv[2]= strdup(buffer);
        SYSCZ(rrd_update(argc, argv), "Error updating rrds");
        count++;
    }

    free(argv);
}

/* *************************************************** */

//aiuta a gestire overflow contatori
unsigned int calc_diff(unsigned int old_val, unsigned int new_val) {
    if(new_val >= old_val) {
        return new_val - old_val;
    } else {
        // overflow occurred
        return (UINT32_MAX - old_val) + new_val + 1;
    }
}

/* *************************************************** */

// Thread per polling SNMP
void* polling_thread(void* arg) {
    agent_info *info = (agent_info *)arg;
    unsigned int prev_ifOutB[info->nIf];
    unsigned int delta_ifOutB[info->nIf];

    struct timespec interval = { .tv_sec = info->step, .tv_nsec = 0 };
    int snmp_ack;
    unsigned int first = 1;

    while (keep_running) {
        printf("[THREAD] Polling SNMP data...\n");
        unsigned int ifOutB[info->nIf];
        snmp_ack = 0;

        // recupero bytes in uscita dalle interfacce
        getIfOutBytes(info->ss,info->nIf,ifOutB, &snmp_ack);
        if(!snmp_ack){
            if(first){
                update_rrd(info->base_dir, info->nIf, ifOutB);
                memcpy(prev_ifOutB, ifOutB, sizeof(prev_ifOutB));
                first=0;
            }else{
                for(int i = 0; i<info->nIf ; i++){
                    delta_ifOutB[i] = calc_diff(prev_ifOutB[i], ifOutB[i]);
                    prev_ifOutB[i] = ifOutB[i];
                }
                update_rrd(info->base_dir, info->nIf, delta_ifOutB);
            }
        }


        // Attesa con possibilità di interruzione da segnale
        if (nanosleep(&interval, NULL) == -1 && errno == EINTR) {
            break;  // interrotto da segnale
        }
    }

    printf("[THREAD] Polling thread exiting.\n");
    return NULL;
}

/* *************************************************** */

static void help(){ //TODO aggiungere skipzero, verbose
    printf("Usage: port_similarity -h <hostname> | -l | -c <basedir> [-a <alpha>][-t <threshold>]\n"
           "                                    [-e <end>][-s <start>][-S <step][-v][-z]\n"
           "-e <end>       | RRD end time. Default %s\n"
           "-s <start>     | RRD start time. Default %s\n"
           "-h <hostname>  | Hostname or IP address of the agent\n"
           "-c <basedir>   | Analyze similarity in RRD files in specified basedir (without SNMP polling)"
           "-t <threshold> | Similarity threshold. Default %u (0 == alike)\n"
           "-l             | Use localhost instead of specifying hostname (%s)\n"
           "-S <step>      | Set RRD step. Valid range >0. Default %d\n"
           "-v             | Verbose\n"
           "-z             | Skip zero RRDs during comparison\n"
            ,
           DEFAULT_END,DEFAULT_START, DEFAULT_THRESHOLD, DEFAULT_AGENT, DEFAULT_STEP);

    printf("\n\nExample: port_similarity -l\n");

    printf("\n\nGoal: find similar port on SNMP manager\n");
    exit(0);
}

/* *************************************************** */

int main(int argc, char *argv[]) {
    agent_info *info;
    int c;
    time_t start, end;
    char *hostname = NULL, *basedir = NULL, *start_s, *end_s;
    u_int step;
    pthread_t poll_thread;
    rrd_time_value_t start_tv, end_tv;

    SYSCN(info, ndpi_calloc(sizeof(agent_info), 1), "Calloc struct agent_info")

    /* Default */

    start_s = DEFAULT_START;
    end_s = DEFAULT_END;
    similarity_threshold = DEFAULT_THRESHOLD;
    step = DEFAULT_STEP;

    // Imposta handler per SIGINT
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction SIGTERM");
        exit(1);
    }

    while((c = getopt(argc, argv, "c:h:t:lS:vzs:e:")) != '?') {
        if(c == -1) break;

        switch(c) {
            case 'c':
                basedir = optarg;
                break;

            case 'h':
                hostname = optarg;
                break;

            case 't':
                similarity_threshold = atoi(optarg);
                break;

            case 'l':
                hostname = DEFAULT_AGENT;
                step = 10;
                break;

            case 'z':
                skip_zero = 1;
                break;

            case 'v':
                verbose = 1;
                break;

            case 'S':
            {
                int s = atoi(optarg);

                if(s > 0)
                    step = s;
                else
                    printf("Discarding -s: valid range is >0\n");
            }
                break;

            case 's':
                start_s = optarg;
                break;

            case 'e':
                end_s = optarg;
                break;

            default:
                help();
                break;
        }
    }

    if(hostname != NULL && basedir == NULL){ //faccio polling snmp
        //inizializzo sessione
        init_session(&info->ss, hostname, DEFAULT_COMMUNITY);
        // recupero il numero di interfacce dell'agent
        SYSCN(info->rrds, ndpi_calloc(sizeof(rrd_file_stats), MAX_NUM_RRDS), "Not enough memory! \n");
        info->nIf = getNumIf(info->ss);
        char base_dir[64];
        snprintf(base_dir, sizeof(base_dir), "%s/%s", RRD_FILES, hostname);
        info->base_dir = strdup(base_dir);
        printf("%s\n", base_dir);
        info->step = step;
        init_rrd(info->base_dir, info->step, info->nIf, info);

        start = time(NULL);

        SYSCZ(pthread_create(&poll_thread, NULL, polling_thread, (void*)info), "Error creating polling thread");

        SYSCZ(pthread_join(poll_thread, NULL), "Error waiting polling thread");

        end = time(NULL);

        printf("from %ld to %ld \n", start, end);
    }else if(hostname == NULL && basedir != NULL){ //faccio solo analisi similarità
        SYSCN(info->rrds, ndpi_calloc(sizeof(rrd_file_stats), MAX_NUM_RRDS), "Not enough memory! \n");
        u_int num_rrds;
        find_rrds(basedir, info->rrds, &num_rrds);
        info->nIf=num_rrds;

        if((rrd_parsetime(start_s, &start_tv) != NULL)) {
            printf("Unable to parse start time %s\n", start_s);
            return(-1);
        }

        if((rrd_parsetime(end_s, &end_tv) != NULL)) {
            printf("Unable to parse end time %s\n", end_s);
            return(-1);
        }

        rrd_proc_start_end(&start_tv, &end_tv, &start, &end);
    }else{
        help();
    }


    /* Read RRD's data */
    for(int i=0; i<info->nIf; i++)
        analyze_rrd(&info->rrds[i], start, end);

    find_rrd_similarities(info->rrds, info->nIf);

    if(verbose) {
        for(int i=0; i<info->nIf; i++)
            printf("%s\t%.1f\t%.1f\n", info->rrds[i].path, info->rrds[i].average, info->rrds[i].stddev);
    }

    for(int i=0; i<info->nIf; i++) {
        ndpi_free_bin(&info->rrds[i].b);
        free(info->rrds[i].path);
    }

    ndpi_free(info);
    snmp_close(info->ss);
    return 0;
}
