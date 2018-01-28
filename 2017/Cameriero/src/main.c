#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <assert.h>

#include "list.h"
#include "log.h"

// IPv4 subnet
struct subnet {
    int begin;
    int end;
    int prefix;
};

// A host found on a subnet.
struct host {
    char* address;
    bool error;
    char result[2048];
    struct host* next;
};

// State of an SNMP scan
struct scan_state {
    char* community;
    size_t community_len;
    unsigned int retries;
    unsigned long timeout;

    struct subnet subnet;

    struct host* hosts;
    size_t hosts_count;
    size_t hosts_tried;

    struct snmp_session* pending_sessions;
    struct snmp_session* sessions_to_close;
    size_t pending_sessions_count;
};

struct oid {
    const char* name;
    oid oid[MAX_OID_LEN];
    size_t oid_len;
} _oid = { "1.3.6.1.2.1.1.5.0" }; // system.sysName.0

// Parses a string of the format "a.b.c.d/e" into a `subnet` struct.
int parse_subnet(struct subnet* net, const char* str) {

    // Splits the subnet in address and prefix
    char* prefix = strchr(str, '/');
    if (prefix == NULL) {
        return 1;
    }
    *prefix = '\0';
    prefix++;

    // Parses the prefix
    net->prefix = atoi(prefix);
    if (net->prefix <= 0 && net->prefix > 32) {
        return 1;
    }

    // Parses the address
    struct in_addr addr;
    if (!inet_aton(str, &addr)) {
        return 1;
    }
    net->begin = ntohl(addr.s_addr);

    // Create a mask from the prefix
    // to make sure that the addres is at the beginning of the subnet
    int mask = ~((1 << (32 - net->prefix)) - 1);
    net->begin = net->begin & mask;
    net->end = net->begin | ~mask;

    return 0;

}

// Returns the dotted notation for an IPv4 address.
// The returned string is allocated in the heap, so it's the caller's
// responsibility to free it.
char* address_to_string(int address) {
    struct in_addr in = { .s_addr = htonl(address) };
    return strdup(inet_ntoa(in));
}

// Frees the memory allocated for the state of the scan
void free_state(struct scan_state* state) {
    LIST_ITERATE(state->hosts, host, struct host, next) {
        free(host->address);
        free(host);
    }
    assert(state->pending_sessions == NULL);
    assert(state->pending_sessions_count == 0);
    assert(state->sessions_to_close == NULL);
    free(state);
}

// Callback executed when we receive a response to an SNMP request
int on_snmp_response(int operation, struct snmp_session* session, int reqid, struct snmp_pdu* pdu, void* context) {
    struct scan_state* state = (struct scan_state*)context;

    // Response successfully received
    if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        LOG(L_INFO, "Host %s: UP", session->peername);

        struct host* host = (struct host*)malloc(sizeof(struct host));
        host->address = strdup(session->peername);
        host->error = pdu->errstat != SNMP_ERR_NOERROR;
        host->next = NULL;
        LIST_PREPEND(state->hosts, host, struct host, next);
        state->hosts_count++;

        struct variable_list* vars = pdu->variables;
        snprint_variable(host->result, sizeof(host->result), vars->name, vars->name_length, vars);
        assert(vars->next_variable == NULL);

        // Mark the session as closeable
        LIST_PREPEND(state->sessions_to_close, session, struct snmp_session, myvoid);

    } else {
        LOG(L_INFO, "Host %s: TIMEOUT", session->peername);

        // Free the string containing the name of the peer in case of error,
        // since we will never show it
        free(session->peername);

        // Here we don't add the session to the closeable list because
        // since there was an error, the SNMP library will automatically close it.
    }

    // Remove the session from the list of pending ones
    LIST_DELETE(state->pending_sessions, session, struct snmp_session, myvoid);
    state->pending_sessions_count--;

    return 1;
}

// Performs the scan of the given subnet keeping at most `parallel` concurrent connections.
void do_scan(struct scan_state* state, int parallel) {
    
    // We add 1 to skip the initial address with all 0.
    int i = state->subnet.begin;
    if (state->subnet.prefix < 32) {
        i++;
    }

    while (true) {
        
        while (state->pending_sessions_count < parallel && i<= state->subnet.end) {

            // Prepare the SNMP session
            struct snmp_session s = { 0 };
            struct snmp_session* session;
            snmp_sess_init(&s);
            s.version = SNMP_VERSION_2c;
            s.peername = address_to_string(i);
            s.community = (u_char*)(state->community);
            s.community_len = state->community_len;
            s.retries = state->retries;
            s.timeout = state->timeout;
            s.callback = on_snmp_response;
            s.callback_magic = state;
            if (!(session = snmp_open(&s))) {
                snmp_perror("Cannot open SNMP session");
                exit(1);
            }

            // We immediately free the string allocated with `address_to_string` since
            // `snmp_open` made a copy that the SNMP library will use internally.
            free(s.peername);

            // Prepare the PDU to send
            struct snmp_pdu* req = snmp_pdu_create(SNMP_MSG_GET);
            snmp_add_null_var(req, _oid.oid, _oid.oid_len);

            // Sends the request
            LOG(L_DEBUG, "Sending request to %s.", session->peername);
            if (snmp_send(session, req)) {
                LIST_PREPEND(state->pending_sessions, session, struct snmp_session, myvoid);
                state->pending_sessions_count++;
                state->hosts_tried++;
            } else {
                snmp_perror("Cannot send SNMP request");
                exit(1);
            }

            i++;

        }

        // Exit if no sessions are pending
        if (state->pending_sessions_count == 0) {
            break;
        }

        // We reached the maximum number of parallel requests,
        // so it's time to suspend.

        int fds = 0, block = 1;
        fd_set fdset;
        struct timeval timeout;
        
        FD_ZERO(&fdset);
        snmp_select_info(&fds, &fdset, &timeout, &block);
        fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);
        if (fds < 0) {
            perror("Select failed");
            exit(1);
        }
        if (fds) {
            snmp_read(&fdset);
        } else {
            snmp_timeout();
        }

        // Close all the sessions marked as closeable
        LIST_ITERATE(state->sessions_to_close, session, struct snmp_session, myvoid) {
            snmp_close(session);
        }
        state->sessions_to_close = NULL;

    }

}

void print_usage(const char* arg) {
    fprintf(stderr, "Usage: %s [-hd] [-c community] [-r retries] [-t timeout] [-p parallel_requests] subnet\n", arg);
}

int main(int argc, char** argv) {

    int log_level = 1;
    int parallel = 4;
    char* community = "public";
    unsigned int retries = 1;
    unsigned long timeout = 400 * 1000; // 0.4s
    char* subnet = NULL;

    // Arguments
    int c;
    while ((c = getopt(argc, argv, "hdc:r:t:p:")) != -1) {
        switch (c) {
            case 'd':
                log_level++;
                break;
            case 'c':
                community = optarg;
                break;
            case 'r':
                retries = atoi(optarg);
                break;
            case 't':
                timeout = atol(optarg) * 1000;
                break;
            case 'p':
                parallel = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    // Checks that the required subnet has been provided
    if (optind >= argc) {
        print_usage(argv[0]);
        exit(1);
    }
    subnet = argv[optind];

    // Prepares the state for the scan
    struct scan_state* state = (struct scan_state*)calloc(1, sizeof(struct scan_state));
    state->community = community;
    state->community_len = strlen(community);
    state->retries = retries;
    state->timeout = timeout;

    // Parses the subnet
    if (parse_subnet(&(state->subnet), subnet) != 0) {
        fprintf(stderr, "Invalid subnet. Please, use the format a.b.c.d/e.\n");
        exit(1);
    }

    // Initialization
    init_snmp("snmpscan");
    LOG_SET_LEVEL(log_level);

    // A bit of logging
    LOG(L_DEBUG, "Community: %s", community);
    LOG(L_DEBUG, "Max parallel requests: %d", parallel);

    // Parse the oids to request
    _oid.oid_len = sizeof(_oid.oid) / sizeof(_oid.oid[0]);
    if (!read_objid(_oid.name, _oid.oid, &_oid.oid_len)) {
        snmp_perror("Cannot parse object id");
        exit(1);
    }

    // Start scan
    LOG(L_DEBUG, "Starting scan.");
    do_scan(state, parallel);
    LOG(L_DEBUG, "Scan finished.");

    printf("\n");

    // Prints the scan results
    printf("Scan results:\n");
    printf("- Total hosts scanned: %lu\n", state->hosts_tried);
    printf("- Hosts up: %lu\n", state->hosts_count);
    printf("\n");
    struct host* host = state->hosts;
    while (host) {
        printf("Host %s: \n", host->address);
        if (host->error) {
            printf("    Error response.\n");
        } else {
            printf("    %s\n", host->result);
        }
        host = host->next;
        if (host != NULL) {
            printf("\n");
        }
    }

    // Frees the whole state
    free_state(state);

    return 0;
}