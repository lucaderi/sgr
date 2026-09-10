#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_BLACKLIST 1024
#define MAX_LINE 256
#ifndef TRAP_IP
#define TRAP_IP "192.0.2.1"
#endif
#define DEFAULT_TRAP_IP "0.0.0.0"

char *blacklist[MAX_BLACKLIST];
size_t bl_count = 0;

void load_blacklist(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Warning: cannot open blacklist file %s\n", path);
        return;
    }
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;
        char *end = p + strlen(p) - 1;
        while (end >= p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        if (*p == '\0' || *p == '#') continue;
        if (bl_count < MAX_BLACKLIST) {
            blacklist[bl_count] = strdup(p);
            bl_count++;
        }
    }
    fclose(f);
    fprintf(stderr, "Loaded %zu blacklist entries\n", bl_count);
}

int is_blacklisted(const char *ip) {
    for (size_t i = 0; i < bl_count; i++) {
        if (strcmp(blacklist[i], ip) == 0) return 1;
    }
    return 0;
}

void send_snmp_trap(const char *trap_ip, int trap_port, const char *community, const char *src, const char *dst) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "snmptrap -v 2c -c %s %s:%d '' .1.3.6.1.4.1.4976.1.1.1 1.3.6.1.4.1.4976.1.1.2 s \"%s->%s\" 2>&1",
             community, trap_ip, trap_port, src, dst);
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "Failed to start snmptrap command\n");
        return;
    }

    char output[1024];
    int printed = 0;
    while (fgets(output, sizeof(output), pipe)) {
        fprintf(stderr, "snmptrap: %s", output);
        printed = 1;
    }

    int status = pclose(pipe);
    if (status == -1) {
        fprintf(stderr, "Failed to run snmptrap command\n");
    } else if (status != 0) {
        fprintf(stderr, "snmptrap failed with exit status %d\n", status);
        if (!printed) {
            fprintf(stderr, "snmptrap returned no output, check that Net-SNMP is installed and reachable.\n");
        }
    } else {
        fprintf(stderr, "SNMP trap sent to %s:%d for %s->%s\n", trap_ip, trap_port, src, dst);
    }
}

void parse_netflow_v5(uint8_t *data, ssize_t len, const char *trap_ip, int trap_port, const char *community) {
    if (len < 24) return;
    uint16_t version = ntohs(*(uint16_t *)(data));
    uint16_t count = ntohs(*(uint16_t *)(data + 2));
    if (version != 5) return;
    ssize_t offset = 24;
    const ssize_t rec_size = 48;
    for (int i = 0; i < count; i++) {
        if (offset + rec_size > len) break;
        uint32_t srcaddr = ntohl(*(uint32_t *)(data + offset));
        uint32_t dstaddr = ntohl(*(uint32_t *)(data + offset + 4));
        struct in_addr sa, da;
        sa.s_addr = htonl(srcaddr);
        da.s_addr = htonl(dstaddr);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &da, dst_ip, sizeof(dst_ip));
        int blacklisted = is_blacklisted(src_ip) || is_blacklisted(dst_ip);
        fprintf(stderr, "Flow record %d: %s -> %s blacklisted=%d\n", i + 1, src_ip, dst_ip, blacklisted);
        if (blacklisted) {
            fprintf(stderr, "Malicious flow detected: %s -> %s\n", src_ip, dst_ip);
            send_snmp_trap(trap_ip, trap_port, community, src_ip, dst_ip);
        }
        offset += rec_size;
    }
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --trap-ip TRAP_IP [--listen-port PORT] [--blacklist FILE] [--community COMMUNITY]\n", prog);
}

int main(int argc, char **argv) {
    int listen_port = 2055;
    char trap_ip[64] = TRAP_IP;
    int trap_port = 162;
    const char *blacklist_file = "blacklist.txt";
    const char *community = "public";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--trap-ip") == 0 && i + 1 < argc) {
            strncpy(trap_ip, argv[++i], sizeof(trap_ip)-1);
        } else if (strcmp(argv[i], "--trap-port") == 0 && i + 1 < argc) {
            trap_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--blacklist") == 0 && i + 1 < argc) {
            blacklist_file = argv[++i];
        } else if (strcmp(argv[i], "--community") == 0 && i + 1 < argc) {
            community = argv[++i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }


    load_blacklist(blacklist_file);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    fprintf(stderr, "Listening NetFlow v5 on 0.0.0.0:%d\n", listen_port);

    while (1) {
        uint8_t buf[65536];
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        parse_netflow_v5(buf, n, trap_ip, trap_port, community);
    }

    close(sock);
    return 0;
}
