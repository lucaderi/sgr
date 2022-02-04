#include "parser.h"

u_int twobytecnc(u_char a, u_char b) {
    return (a << 8) | b;
}

u_int fourbytecnc(u_char a, u_char b, u_char c, u_char d) {
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

u_int get_eth_type(const u_char *packet) {
    return twobytecnc(packet[ETH_PROT_BYTE1], packet[ETH_PROT_BYTE1 + 1]);
}

u_int get_ip4_prot(const u_char *packet) {
    return packet[IP_PROT_BYTE];
}

u_int get_ip4_ihl(const u_char *packet) {
    return (packet[IHL_BYTE] & IHL_BYTE_MASK);
}

u_int get_ip4_totlength(const u_char *packet) {
    return twobytecnc(packet[IP4_TOTLENGTH_OFFST], packet[IP4_TOTLENGTH_OFFST + 1]);
}

u_int get_udp_payload(const u_char *packet) {
    u_int ip_head = get_ip4_ihl(packet) * 4;
    u_int offst = ETH_HEAD_SIZE + ip_head + UDP_LENGTH_OFFST;
    return twobytecnc(packet[offst], packet[offst + 1]);
}

u_int get_tcp_payload(const u_char *packet) {
    u_int ip_head = get_ip4_ihl(packet) * 4;
    u_int offst = ETH_HEAD_SIZE + ip_head + TCP_OFFSET_OFFST;
    u_int tcp_head = ((packet[offst] & TCP_OFFSET_MASK) >> 4) * 4;
    return get_ip4_totlength(packet) - tcp_head - ip_head;
}

u_int get_icmp_payload(const u_char *packet) {
    u_int ip_head = get_ip4_ihl(packet) * 4;
    u_int type = packet[ETH_HEAD_SIZE + ip_head];

    if (type == ICMP_TYPE_DESTUNRCH || type == ICMP_TYPE_TIMEEXCD || type == ICMP_TYPE_PARAMPM ||
        type == ICMP_TYPE_SRCQNCMSG || type == ICMP_TYPE_REDIRM) {
        return ip_head + 12;
    }
    if (type == ICMP_TYPE_ECHOMSG || type == ICMP_TYPE_ECHORPLY) {
        return get_ip4_totlength(packet) - ip_head - 8;
    }
    if (type == ICMP_TYPE_TIMESTMP || type == ICMP_TYPE_TIMESTMPRPLY) {
        return 16;
    }
    if (type == ICMP_TYPE_INFOREQ || type == ICMP_TYPE_INFORLY) {
        return 4;
    }
    return 0;
}

u_int get_ip4_srcaddr(const u_char *packet) {
    return fourbytecnc(packet[IP4_SRCADDR_OFFST + 3], packet[IP4_SRCADDR_OFFST + 2], packet[IP4_SRCADDR_OFFST + 1],
                       packet[IP4_SRCADDR_OFFST]);
}

u_int get_ip4_destaddr(const u_char *packet) {
    return fourbytecnc(packet[IP4_DESTADDR_OFFST + 3], packet[IP4_DESTADDR_OFFST + 2], packet[IP4_DESTADDR_OFFST + 1],
                       packet[IP4_DESTADDR_OFFST]);
}
