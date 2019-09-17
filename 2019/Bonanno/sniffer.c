#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "parser.h"
#include "hash.h"
#include <string.h>

#define TRUE 1
#define FALSE 0
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define BPF_FILTER "ip && (tcp || udp || icmp)"
#define TBSNIFFED_DEFAULT 100
#define TABLE_BUCKETS 16

//Shared pointer the the hashtable
ht_t *table;
u_int sniffcount = 0;
int verbose_mode = FALSE;

void printdata(host_data_t *d) {
    struct in_addr tx_addr;
    struct in_addr rx_addr;
    tx_addr.s_addr = d->ipaddr_tx;
    rx_addr.s_addr = d->ipaddr_rx;
    char tx_buf[IP_STR_MAX];
    char rx_buf[IP_STR_MAX];
    strcpy(tx_buf, inet_ntoa(tx_addr));
    strcpy(rx_buf, inet_ntoa(rx_addr));
    printf("tx_addr: %s\t rx_addr: %s\ttcp: %u \tudp: %u \ticmp: %u\n", tx_buf, rx_buf,
           d->tcp_bytes, d->udp_bytes, d->icmp_bytes);
}

void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    host_data_t new_dt = {0, 0, 0, 0, 0};
    new_dt.ipaddr_tx = get_ip4_srcaddr(packet);
    new_dt.ipaddr_rx = get_ip4_destaddr(packet);
    u_int protocol = get_ip4_prot(packet);
    u_int payload;

    if (protocol == IP_PROT_UDP) {
        payload = get_udp_payload(packet);
        new_dt.udp_bytes = payload;
    }
    if (protocol == IP_PROT_TCP) {
        payload = get_tcp_payload(packet);
        new_dt.tcp_bytes = payload;
    }
    if (protocol == IP_PROT_ICMP) {
        payload = get_icmp_payload(packet);
        new_dt.icmp_bytes = payload;
    }
    if (verbose_mode) {
        printdata(&new_dt);
    }
    hash_insert(table, &new_dt);
    sniffcount++;
}

int main(int argc, char **argv) {

    int opt;
    // specify a pcap file to capture from
    int offline_mode = FALSE;
    // specify a nic name instead of letting pcap autodetect it
    int nic_mode = FALSE;
    // specify the exact number of packets to be captured
    int n_mode = FALSE;
    int tbsniffed = TBSNIFFED_DEFAULT;
    FILE *report;
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 ipaddr;
    struct bpf_program fp;
    table = (ht_t *) malloc(sizeof(ht_t));
    hash_init(table, TABLE_BUCKETS);

    while ((opt = getopt(argc, argv, "vo:n:d:")) != -1) {
        switch (opt) {
            case 'd' :
                nic_mode = TRUE;
                device = optarg;
                break;
            case 'o' :
                if (!nic_mode) {
                    offline_mode = TRUE;
                    device = optarg;
                    if (!n_mode)
                        tbsniffed = -1;
                }
                break;
            case 'v' :
                verbose_mode = TRUE;
                break;
            case 'n':
                n_mode = TRUE;
                tbsniffed = atoi(optarg);
                break;
            default : /* '?' */
                printf("Usage: %s [-v] [-o filename] [-n packets]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    printf("verbose= %d; offline_mode= %d; tbsniffed= %d\n", verbose_mode, offline_mode, tbsniffed);

    report = fopen("report.js", "w+");
    if (report == NULL) {
        printf("Error opening report.js");
        return EXIT_FAILURE;
    }

    // Skips NIC scanning and open a pcap file from arguments
    if (offline_mode) {
        goto offline;
    }

    // Finding the device
    if (!nic_mode) {
        device = pcap_lookupdev(error_buffer);
    }
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return EXIT_FAILURE;
    }
    printf("Network device found: %s\n", device);

    //Finding device infos
    if (pcap_lookupnet(device, &ipaddr, &netmask, error_buffer) == PCAP_ERROR) {
        printf("Error finding informations on %s: %s\n", device, error_buffer);
        return EXIT_FAILURE;
    }

    //Opening the pcap session
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", device, error_buffer);
        return EXIT_FAILURE;
    }

    //Opening a pcap file (offline mode)
    offline:
    if (offline_mode) {
        handle = pcap_open_offline(device, error_buffer);
        if (handle == NULL) {
            printf("Couldn't open file %s: %s\n", device, error_buffer);
            return EXIT_FAILURE;
        }
    }

    printf("Session start\n");

    //Compiling the bpf filter
    if (pcap_compile(handle, &fp, BPF_FILTER, 0, ipaddr)) {
        printf("Couldn't compile filer %s: %s\n", BPF_FILTER, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    printf("Filter successfully compiled\n");

    //Filter installation
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Couldn't install filer %s: %s\n", BPF_FILTER, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    printf("Filter successfully installed\n");

    //Loop starts
    if (pcap_loop(handle, tbsniffed, pkt_process, NULL) == PCAP_ERROR) {
        printf("Error during capture\n");
        return EXIT_FAILURE;
    }

    fprintf(report, "const jsonInfo = {\n\"device\":\"%s\",\n\"count\":%u\n}\n", device, sniffcount);
    hash_to_json(report, table);
    hash_free(table);
    pcap_close(handle);
    fclose(report);
    return EXIT_SUCCESS;

}
