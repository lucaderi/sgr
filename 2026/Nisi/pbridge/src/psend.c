#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Function prototypes */
void print_packet_hex(const unsigned char *packet, int len);
void send_packet(pcap_t *handle, const unsigned char *packet, int len);
void usage(char *progname);

/* Hardcoded packet examples */

/* Example 1: Simple Ethernet frame with dummy data */
const unsigned char packet_simple[] = {
    /* Destination MAC (broadcast) */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    /* Source MAC (random) */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    /* Ethertype (0x0800 = IPv4) */
    0x08, 0x00,
    /* Payload - just some dummy data */
    'H', 'e', 'l', 'l', 'o', ' ', 'P', 'a', 'c', 'k', 'e', 't', '!',
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};

/* Example 2: ARP request */
const unsigned char packet_arp[] = {
    /* Ethernet header */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Destination: broadcast */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* Source: 00:11:22:33:44:55 */
    0x08, 0x06,                           /* Type: ARP */
    
    /* ARP header */
    0x00, 0x01,                           /* Hardware type: Ethernet */
    0x08, 0x00,                           /* Protocol type: IP */
    0x06,                                 /* Hardware size: 6 */
    0x04,                                 /* Protocol size: 4 */
    0x00, 0x01,                           /* Opcode: request (1) */
    
    /* Sender MAC */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    /* Sender IP: 192.168.1.100 */
    0xc0, 0xa8, 0x01, 0x64,
    
    /* Target MAC (zero for request) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Target IP: 192.168.1.1 */
    0xc0, 0xa8, 0x01, 0x01
};

/* Example 3: ICMP Echo Request (ping) */
const unsigned char packet_icmp[] = {
    /* Ethernet header */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Destination: broadcast */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* Source: 00:11:22:33:44:55 */
    0x08, 0x00,                           /* Type: IPv4 */
    
    /* IP header (20 bytes) */
    0x45,                                 /* Version 4, header length 5 */
    0x00,                                 /* DSCP and ECN */
    0x00, 0x3c,                           /* Total length: 60 bytes */
    0x12, 0x34,                           /* Identification */
    0x40, 0x00,                           /* Flags and fragment offset */
    0x40,                                 /* TTL: 64 */
    0x01,                                 /* Protocol: ICMP */
    0x00, 0x00,                           /* Header checksum (will be incorrect) */
    0xc0, 0xa8, 0x01, 0x64,               /* Source IP: 192.168.1.100 */
    0xc0, 0xa8, 0x01, 0x01,               /* Dest IP: 192.168.1.1 */
    
    /* ICMP header (8 bytes) + data */
    0x08,                                 /* Type: Echo Request */
    0x00,                                 /* Code: 0 */
    0x00, 0x00,                           /* Checksum (will be incorrect) */
    0x12, 0x34,                           /* Identifier */
    0x00, 0x01,                           /* Sequence number */
    /* ICMP data (padding) */
    'p', 'i', 'n', 'g', ' ', 'd', 'a', 't', 'a'
};

/* Example 4: TCP SYN packet */
const unsigned char packet_tcp_syn[] = {
    /* Ethernet header */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Destination: broadcast */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* Source: 00:11:22:33:44:55 */
    0x08, 0x00,                           /* Type: IPv4 */
    
    /* IP header (20 bytes) */
    0x45,                                 /* Version 4, header length 5 */
    0x00,                                 /* DSCP and ECN */
    0x00, 0x30,                           /* Total length: 48 bytes */
    0x12, 0x34,                           /* Identification */
    0x40, 0x00,                           /* Flags and fragment offset */
    0x40,                                 /* TTL: 64 */
    0x06,                                 /* Protocol: TCP */
    0x00, 0x00,                           /* Header checksum (will be incorrect) */
    0xc0, 0xa8, 0x01, 0x64,               /* Source IP: 192.168.1.100 */
    0xc0, 0xa8, 0x01, 0x01,               /* Dest IP: 192.168.1.1 */
    
    /* TCP header (20 bytes) */
    0x30, 0x39,                           /* Source port: 12345 */
    0x00, 0x50,                           /* Dest port: 80 */
    0x00, 0x00, 0x00, 0x00,               /* Sequence number: 0 */
    0x00, 0x00, 0x00, 0x00,               /* Ack number: 0 */
    0x50,                                 /* Data offset: 5, Reserved: 0 */
    0x02,                                 /* Flags: SYN */
    0x71, 0x10,                           /* Window size: 28976 */
    0x00, 0x00,                           /* Checksum (will be incorrect) */
    0x00, 0x00                            /* Urgent pointer */
};

/* Example 5: Custom raw packet */
const unsigned char packet_custom[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  /* Custom header */
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xde, 0xad, 0xbe, 0xef,               /* Magic bytes */
    'C', 'U', 'S', 'T', 'O', 'M',
    0x00, 0x11, 0x22, 0x33,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa
};

/* Packet information structure */
struct packet_info {
    const unsigned char *data;
    int len;
    const char *name;
    const char *description;
};

/* Array of available packets */
struct packet_info packets[] = {
    {packet_simple, sizeof(packet_simple), "simple", "Simple Ethernet frame with text payload"},
    {packet_arp, sizeof(packet_arp), "arp", "ARP request for 192.168.1.1"},
    {packet_icmp, sizeof(packet_icmp), "icmp", "ICMP Echo Request (ping)"},
    {packet_tcp_syn, sizeof(packet_tcp_syn), "tcp_syn", "TCP SYN packet to port 80"},
    {packet_custom, sizeof(packet_custom), "custom", "Custom raw packet"},
    {NULL, 0, NULL, NULL}
};

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *packet_name = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet = NULL;
    int packet_len = 0;
    const char *packet_desc = NULL;
    int count = 1;
    int i, opt;

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "i:p:c:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                packet_name = optarg;
                break;
            case 'c':
                count = atoi(optarg);
                if (count <= 0) count = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    /* Check required arguments */
    if (interface == NULL) {
        fprintf(stderr, "Error: Network interface is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Find the requested packet */
    if (packet_name != NULL) {
        for (i = 0; packets[i].data != NULL; i++) {
            if (strcmp(packets[i].name, packet_name) == 0) {
                packet = packets[i].data;
                packet_len = packets[i].len;
                packet_desc = packets[i].description;
                break;
            }
        }
        
        if (packet == NULL) {
            fprintf(stderr, "Error: Unknown packet type '%s'\n", packet_name);
            fprintf(stderr, "Available packet types:\n");
            for (i = 0; packets[i].data != NULL; i++) {
                fprintf(stderr, "  %-10s - %s\n", packets[i].name, packets[i].description);
            }
            return 1;
        }
    } else {
        /* Default to ARP packet if none specified */
        packet = packet_arp;
        packet_len = sizeof(packet_arp);
        packet_desc = "ARP request (default)";
    }

    /* Open pcap handle */
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return 1;
    }

    /* Print packet information */
    printf("Interface: %s\n", interface);
    printf("Packet type: %s\n", packet_desc);
    printf("Packet length: %d bytes\n", packet_len);
    printf("Sending count: %d\n", count);
    printf("\nPacket hex dump:\n");
    print_packet_hex(packet, packet_len);
    printf("\n");

    /* Send the packet(s) */
    for (i = 0; i < count; i++) {
        printf("Sending packet %d/%d...\n", i + 1, count);
        send_packet(handle, packet, packet_len);
        
        if (i < count - 1) {
            usleep(100000); /* 100ms delay between packets */
        }
    }

    printf("Done!\n");

    /* Cleanup */
    pcap_close(handle);
    return 0;
}

void print_packet_hex(const unsigned char *packet, int len) {
    int i, j;
    
    for (i = 0; i < len; i += 16) {
        /* Print offset */
        printf("%04x: ", i);
        
        /* Print hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", packet[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" ");
        
        /* Print ASCII representation */
        for (j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = packet[i + j];
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        
        printf("\n");
    }
}

void send_packet(pcap_t *handle, const unsigned char *packet, int len) {
    if (pcap_inject(handle, packet, len) == -1) {
        fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
        exit(1);
    }
}

void usage(char *progname) {
    fprintf(stderr, "Usage: %s -i <interface> [options]\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>   Network interface to use (required)\n");
    fprintf(stderr, "  -p <type>        Packet type to send (default: arp)\n");
    fprintf(stderr, "  -c <count>       Number of packets to send (default: 1)\n");
    fprintf(stderr, "  -h               Show this help message\n");
    fprintf(stderr, "\nAvailable packet types:\n");
    
    for (int i = 0; packets[i].data != NULL; i++) {
        fprintf(stderr, "  %-10s - %s\n", packets[i].name, packets[i].description);
    }
}