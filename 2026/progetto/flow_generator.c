#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

void pack_uint16(unsigned char *buf, int offset, uint16_t v) { *(uint16_t *)(buf+offset) = htons(v); }
void pack_uint32(unsigned char *buf, int offset, uint32_t v) { *(uint32_t *)(buf+offset) = htonl(v); }

void build_v5_packet(unsigned char *buf, const char *src_ip, const char *dst_ip) {
    uint16_t version = 5;
    uint16_t count = 1;
    uint32_t sys_uptime = (uint32_t)(time(NULL) * 1000) & 0xFFFFFFFF;
    uint32_t unix_secs = (uint32_t)time(NULL);
    uint32_t unix_nsecs = 0;
    uint32_t flow_sequence = 1;
    uint8_t engine_type = 0;
    uint8_t engine_id = 0;
    uint16_t sampling_interval = 0;
    pack_uint16(buf, 0, version);
    pack_uint16(buf, 2, count);
    pack_uint32(buf, 4, sys_uptime);
    pack_uint32(buf, 8, unix_secs);
    pack_uint32(buf, 12, unix_nsecs);
    pack_uint32(buf, 16, flow_sequence);
    buf[20] = engine_type;
    buf[21] = engine_id;
    pack_uint16(buf, 22, sampling_interval);
    uint32_t src = inet_addr(src_ip);
    uint32_t dst = inet_addr(dst_ip);
    pack_uint32(buf, 24, ntohl(src));
    pack_uint32(buf, 28, ntohl(dst));
    pack_uint32(buf, 32, 0);
    pack_uint16(buf, 36, 0);
    pack_uint16(buf, 38, 0);
    pack_uint32(buf, 40, 1);
    pack_uint32(buf, 44, 100);
    pack_uint32(buf, 48, unix_secs);
    pack_uint32(buf, 52, unix_secs);
    pack_uint16(buf, 56, htons(1234));
    *(uint16_t *)(buf+56) = htons(1234);
    *(uint16_t *)(buf+58) = htons(80);
    buf[60] = 0; 
    buf[61] = 0;
    buf[62] = 6; 
    buf[63] = 0;
    pack_uint16(buf, 64, 0);
    pack_uint16(buf, 66, 0);
    buf[68] = 0; 
    buf[69] = 0;
    pack_uint16(buf, 70, 0);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s COLLECTOR_IP COLLECTOR_PORT SRC_IP DST_IP\n", argv[0]);
        return 1;
    }
    const char *collector_ip = argv[1];
    int collector_port = atoi(argv[2]);
    const char *src = argv[3];
    const char *dst = argc > 4 ? argv[4] : "192.0.2.100";

    unsigned char pkt[24+48];
    memset(pkt, 0, sizeof(pkt));
    build_v5_packet(pkt, src, dst);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_aton(collector_ip, &addr.sin_addr);
    addr.sin_port = htons(collector_port);

    ssize_t sent = sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) perror("sendto");
    else printf("Sent NetFlow v5 packet %s -> %s to %s:%d\n", src, dst, collector_ip, collector_port);
    close(sock);
    return 0;
}
