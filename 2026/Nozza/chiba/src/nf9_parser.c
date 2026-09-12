#include "nf9_parser.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> 

#define MAX_TEMPLATES 128

#define NF9_IN_BYTES         1
#define NF9_IN_PKTS          2
#define NF9_PROTOCOL         4
#define NF9_L4_SRC_PORT      7
#define NF9_IPV4_SRC_ADDR    8
#define NF9_L4_DST_PORT      11
#define NF9_IPV4_DST_ADDR    12
#define NF9_IPV6_SRC_ADDR    27
#define NF9_IPV6_DST_ADDR    28

struct nf9_header {
    u_int16_t version;
    u_int16_t count;
    u_int32_t sys_uptime;
    u_int32_t unix_secs;
    u_int32_t package_sequence;
    u_int32_t source_id;
} __attribute__((packed));

struct nf9_flowset_header {
    u_int16_t flowset_id;
    u_int16_t length;
} __attribute__((packed));

struct nf9_template {
    u_int16_t template_id;
    u_int32_t source_id;    
    u_int16_t total_len;    

    int16_t off_ipv4_src, len_ipv4_src;
    int16_t off_ipv4_dst, len_ipv4_dst;
    int16_t off_ipv6_src, len_ipv6_src;
    int16_t off_ipv6_dst, len_ipv6_dst;
    int16_t off_pkts, len_pkts;
    int16_t off_bytes, len_bytes;
    int16_t off_sport, len_sport;
    int16_t off_dport, len_dport;
    int16_t off_prot, len_prot;
};

static struct nf9_template templates[MAX_TEMPLATES];
static int template_count = 0;

static struct nf9_template *get_template(u_int16_t template_id, u_int32_t source_id) {
    for (int i = 0; i < template_count; i++) {
        if (templates[i].template_id == template_id && templates[i].source_id == source_id) {
            return &templates[i];
        }
    }
    return NULL;
}

static struct nf9_template *add_template(u_int16_t template_id, u_int32_t source_id) {
    struct nf9_template *tmpl = get_template(template_id, source_id);
    if (tmpl == NULL) {
        if (template_count >= MAX_TEMPLATES) tmpl = &templates[0]; 
        else tmpl = &templates[template_count++];
    }
    
    memset(tmpl, 0, sizeof(struct nf9_template));
    tmpl->template_id = template_id;
    tmpl->source_id = source_id;
    tmpl->off_ipv4_src = tmpl->off_ipv4_dst = -1;
    tmpl->off_ipv6_src = tmpl->off_ipv6_dst = -1;
    tmpl->off_pkts = tmpl->off_bytes = -1;
    tmpl->off_sport = tmpl->off_dport = tmpl->off_prot = -1;
    return tmpl;
}

static void map_ipv4_to_ipv6(u_int32_t ipv4, u_int8_t *ipv6_out) {
    memset(ipv6_out, 0, 10);      
    ipv6_out[10] = 0xFF;          
    ipv6_out[11] = 0xFF;
    memcpy(ipv6_out + 12, &ipv4, 4); 
}

static u_int64_t get_int_value(const u_int8_t *ptr, int len) {
    if (len == 1) return *ptr;
    if (len == 2) return ntohs(*(u_int16_t*)ptr);
    if (len == 4) return ntohl(*(u_int32_t*)ptr);
    if (len == 8) {
        u_int32_t high = ntohl(*(u_int32_t*)ptr);
        u_int32_t low = ntohl(*(u_int32_t*)(ptr + 4));
        return ((u_int64_t)high << 32) | low;
    }
    return 0;
}

void parse_nf9_packet(const u_int8_t *buffer, int length, rbuffer *rb) {
    if (length < (int)sizeof(struct nf9_header)) return;

    struct nf9_header *header = (struct nf9_header *)buffer;
    if (ntohs(header->version) != 9) return; 

    u_int16_t count = ntohs(header->count);
    u_int32_t unix_secs = ntohl(header->unix_secs);
    u_int32_t source_id = ntohl(header->source_id);

    int offset = sizeof(struct nf9_header); 

    for (int i = 0; i < count && offset + (int)sizeof(struct nf9_flowset_header) <= length; i++) {
        struct nf9_flowset_header *fs_hdr = (struct nf9_flowset_header *)(buffer + offset);
        u_int16_t flowset_id = ntohs(fs_hdr->flowset_id);
        u_int16_t flowset_len = ntohs(fs_hdr->length);

        if (flowset_len == 0 || offset + flowset_len > length) break;

        /* Template records */
        if (flowset_id == 0) { 
            int t_offset = offset + sizeof(struct nf9_flowset_header);
            
            while (t_offset + 4 <= offset + flowset_len) {
                u_int16_t template_id = ntohs(*(u_int16_t*)(buffer + t_offset));
                u_int16_t field_count = ntohs(*(u_int16_t*)(buffer + t_offset + 2));
                t_offset += 4;

                struct nf9_template *tmpl = add_template(template_id, source_id);
                u_int16_t current_field_offset = 0;

                for (int f = 0; f < field_count && t_offset + 4 <= offset + flowset_len; f++) {
                    u_int16_t f_type = ntohs(*(u_int16_t*)(buffer + t_offset));
                    u_int16_t f_len = ntohs(*(u_int16_t*)(buffer + t_offset + 2));
                    
                    switch (f_type) {
                        case NF9_IPV4_SRC_ADDR: 
                            tmpl->off_ipv4_src = current_field_offset; tmpl->len_ipv4_src = f_len; break;
                        case NF9_IPV4_DST_ADDR: 
                            tmpl->off_ipv4_dst = current_field_offset; tmpl->len_ipv4_dst = f_len; break;
                        case NF9_IPV6_SRC_ADDR: 
                            tmpl->off_ipv6_src = current_field_offset; tmpl->len_ipv6_src = f_len; break;
                        case NF9_IPV6_DST_ADDR: 
                            tmpl->off_ipv6_dst = current_field_offset; tmpl->len_ipv6_dst = f_len; break;
                        case NF9_IN_PKTS:       
                            tmpl->off_pkts = current_field_offset; tmpl->len_pkts = f_len; break;
                        case NF9_IN_BYTES:      
                            tmpl->off_bytes = current_field_offset; tmpl->len_bytes = f_len; break;
                        case NF9_L4_SRC_PORT:   
                            tmpl->off_sport = current_field_offset; tmpl->len_sport = f_len; break;
                        case NF9_L4_DST_PORT:   
                            tmpl->off_dport = current_field_offset; tmpl->len_dport = f_len; break;
                        case NF9_PROTOCOL:  
                            tmpl->off_prot = current_field_offset; tmpl->len_prot = f_len; break;
                    }
                    current_field_offset += f_len; 
                    t_offset += 4; 
                }
                tmpl->total_len = current_field_offset;
            }
        } 

        /* Data records */
        else if (flowset_id > 255) { 
            struct nf9_template *tmpl = get_template(flowset_id, source_id);
            if (tmpl != NULL && tmpl->total_len > 0) {
                int d_offset = offset + sizeof(struct nf9_flowset_header);
                
                while (d_offset + tmpl->total_len <= offset + flowset_len) {
                    flow_data rbd;
                    memset(&rbd, 0, sizeof(rbd));
                    
                    rbd.start_time = unix_secs; 
                    rbd.end_time = unix_secs;

                    if (tmpl->off_ipv4_src >= 0) {
                        u_int32_t ip = *(u_int32_t*)(buffer + d_offset + tmpl->off_ipv4_src);
                        map_ipv4_to_ipv6(ip, rbd.srcaddr);
                    } else if (tmpl->off_ipv6_src >= 0) {
                        memcpy(rbd.srcaddr, buffer + d_offset + tmpl->off_ipv6_src, 16);
                    }

                    if (tmpl->off_ipv4_dst >= 0) {
                        u_int32_t ip = *(u_int32_t*)(buffer + d_offset + tmpl->off_ipv4_dst);
                        map_ipv4_to_ipv6(ip, rbd.dstaddr);
                    } else if (tmpl->off_ipv6_dst >= 0) {
                        memcpy(rbd.dstaddr, buffer + d_offset + tmpl->off_ipv6_dst, 16);
                    }

                    if (tmpl->off_pkts >= 0) 
                        rbd.dPkts = get_int_value(buffer + d_offset + tmpl->off_pkts, tmpl->len_pkts);
                    if (tmpl->off_bytes >= 0) 
                        rbd.dOctets = get_int_value(buffer + d_offset + tmpl->off_bytes, tmpl->len_bytes);
                    if (tmpl->off_sport >= 0) 
                        rbd.srcport = get_int_value(buffer + d_offset + tmpl->off_sport, tmpl->len_sport);
                    if (tmpl->off_dport >= 0) 
                        rbd.dstport = get_int_value(buffer + d_offset + tmpl->off_dport, tmpl->len_dport);
                    if (tmpl->off_prot >= 0) 
                        rbd.prot = get_int_value(buffer + d_offset + tmpl->off_prot, tmpl->len_prot);

                    ring_buffer_put(rb, rbd);

                    d_offset += tmpl->total_len; 
                }
            }
        }
        offset += flowset_len; 
    }
}
