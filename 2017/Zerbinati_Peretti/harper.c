#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include "macToVendor.h"
#include "ipMacList.h"


#define DEFAULT_DUMP_FILENAME "dump_ht.csv"

/* global vars */
char* device = NULL;        /* device name */
int promisc = 0;            /* promiscue mode */
int snaplen = 64;           /* MAX length of packets */
bpf_u_int32 maskp;          /* net order subnet mask */
bpf_u_int32 netp;           /* net order ip address*/
unsigned int interval = 10; /* interval between 2 injects in millisecs */
unsigned int timeout = 1;   /* interval between last inject and closure of capture  */
int rpt = 1;                /* #ARPrequest for each IP */
struct in_addr src_ip_addr;
unsigned char src_mac_addr[6];


void print_usage() {
  fprintf(stdout, "USAGE:\nharper [-i interface] [-r # of request] [-t interval between requests]\n");
}

/**
 * getMacIp() copies MAC and IP of the interface if_name to the buffer pointed by my_mac and to struct pointed by my_ip
 * Return 0 if successful, -1 otherwise
 */
int getMacIp(unsigned char* my_mac, struct in_addr * my_ip, unsigned char* if_name) {
  // Open a socket
  struct ifreq ifr;
  int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (fd==-1) {
    fprintf(stderr, "Socket error");
    return -1;
  }
  // Prepare ioctl with the interface name
  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
  // Call iotl for MAC address
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 1) {
    fprintf(stderr, "Ioctl error retrieving MAC\n");
    close(fd);
    return -1;
  }
  memcpy(my_mac, (unsigned char*) ifr.ifr_hwaddr.sa_data, 6*sizeof(unsigned char));

  struct ifreq ifrip;
  // Prepare ioctl with the interface name
  strncpy(ifrip.ifr_name, if_name, sizeof(ifrip.ifr_name));
  // Call iotl for IP address
  if (ioctl(fd, SIOCGIFADDR, &ifrip) == 1) {
    fprintf(stderr, "Ioctl error retrieving IP\n");
    close(fd);
    return -1;
  }
  memcpy(my_ip, &((struct sockaddr_in*)&ifrip.ifr_addr)->sin_addr, sizeof(struct in_addr));

  close(fd);
  return 0;
}

/**
 * packetBuild() forges an ARP request for dst_ip_string and copies it to the buffer pointed by pkt
 */
int packetBuild(const char* dst_ip_string, unsigned char* pkt) {

  struct in_addr dst_ip_addr;   // IP receiver
  struct ether_header eth_hdr;  // ethernet
  struct ether_arp arp_req;     // arp

  /* 1- Forge ethernet header*/
  memcpy(eth_hdr.ether_shost, src_mac_addr, sizeof(eth_hdr.ether_shost));
  memset(eth_hdr.ether_dhost,0xff,sizeof(eth_hdr.ether_dhost)); //broadcast

  eth_hdr.ether_type=htons(ETH_P_ARP); //0x0806 arp

  /* 2- Forge ARP request */
  arp_req.arp_hrd=htons(ARPHRD_ETHER);
  arp_req.arp_pro=htons(ETH_P_IP);
  arp_req.arp_hln=ETHER_ADDR_LEN;
  arp_req.arp_pln=sizeof(in_addr_t);
  arp_req.arp_op=htons(ARPOP_REQUEST);
  memset(&arp_req.arp_tha,0,sizeof(arp_req.arp_tha));
  memcpy(&arp_req.arp_sha, src_mac_addr,sizeof(arp_req.arp_sha));
  memcpy(&arp_req.arp_spa, &(src_ip_addr.s_addr), sizeof(arp_req.arp_spa));
  // Convert receiverIp
  if (!inet_aton(dst_ip_string, &dst_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address", dst_ip_string);
       return -1;
    }
  memcpy(&arp_req.arp_tpa, &dst_ip_addr.s_addr, sizeof(arp_req.arp_tpa));

  /* Combine ETHERNET e ARP into the packet */
  memcpy(pkt, &eth_hdr, sizeof(eth_hdr));
  memcpy(pkt + sizeof(eth_hdr), &arp_req, sizeof(arp_req));

  return 0;
}


/**
 * INJECT THREAD
 * Uses pcap library to send a rpt number of ARP request to every IP of the subnet.
 */
void* inject_arp() {
  unsigned char pkt_to_send[ sizeof(struct ether_header) + sizeof(struct ether_arp) ];
  bpf_u_int32 neth =  ntohl(netp);        /* host order ip */
  bpf_u_int32 maskh = ntohl(maskp);       /* host order mask */
  bpf_u_int32 first_ip = neth & maskh;    /* first IP of the subnet */
  bpf_u_int32 last_ip = ( neth + (~maskh) );  /* last IP of the subnet */
  bpf_u_int32 curr_ip;
  bpf_u_int32 curr_ip_net;
  struct in_addr curr_ip_addr;
  char* curr;
  pcap_t *pd_inj;
  char errbuf[PCAP_ERRBUF_SIZE];
  int i, numips;
  struct timespec ts;
  ts.tv_sec = interval / 1000;
  ts.tv_nsec = (interval % 1000) * 1000000;

  numips = last_ip - first_ip;

  if((pd_inj = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return NULL;
  }

  for (i=0; i<rpt; i++) {
    for (curr_ip=first_ip; curr_ip<=last_ip; curr_ip++) {
      // convert to dot notation (netorder)
      curr_ip_net = htonl(curr_ip);
      curr_ip_addr.s_addr = curr_ip_net;
      curr = inet_ntoa(curr_ip_addr);
      // Forge packet
      if (packetBuild(curr, pkt_to_send) == -1) {
	      printf("pktBuild: %s\n", errbuf);
	      pcap_close(pd_inj);
	      return NULL;
      }
      // Inject packet
      if (pcap_inject(pd_inj, pkt_to_send, sizeof(pkt_to_send))==-1) {
	      printf("pcap_inject: %s\n", errbuf);
	      pcap_close(pd_inj);
	      return NULL;
      }
      // wait befor next inject
      nanosleep(&ts, NULL);
    }
  }
  pcap_close(pd_inj);
  return 0;
}  /* END INJECT THREAD */


/**
 * process_arp() processes the received packet p and store retrieved info in the Hash Table
 */
void process_arp(u_char* device_id,
		 const struct pcap_pkthdr *h,
		 const u_char *p) {
  struct ether_header ehdr;
  struct ether_arp arph;
  u_short eth_type;
  struct in_addr src_ip_addr;
  char short_mac[20];  // 6 chars indeed
  char* ip_str;

  // Copy ethernet
  memcpy(&ehdr, p, sizeof(struct ether_header));
  eth_type = ntohs(ehdr.ether_type);
  // Check if packets are ARP (btw the pcap filter is already set, so it's quite useless)
  if(eth_type == ETH_P_ARP) {
    /* Copy ARP */
    memcpy(&arph, p+sizeof(struct ether_header), sizeof(struct ether_arp));
  	memcpy(&src_ip_addr.s_addr, &arph.arp_spa, sizeof(arph.arp_spa));
  	ip_str = inet_ntoa(src_ip_addr);
  #ifdef DEBUG
  	fprintf(stdout, "Received ARP from: %s with ip: %s \n", macToStr(arph.arp_sha), ip_str);
  #endif
    // Store infos in the Hash Table
  	insert(arph.arp_sha, src_ip_addr, time(NULL));
    }
}

/**
 * Cleaner() is called before capture_arp thread exits
 */
void cleaner(void *arg) {
  pcap_t *pd = (pcap_t*) arg;
  pcap_breakloop(pd);
  pcap_close( pd );
  return;
}
/**
 * CAPTURE THREAD
 * Uses pcap library to capture filtered ARP reply packets and process them calling process_arp()
 */
void* capture_arp() {
  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];
  char* bpfFilter = "arp && arp[6:2] = 2";  // arp[x:y] - from byte 6 for 2 bytes (arp.opcode ==2 -> reply)
  struct bpf_program fcode;

  // fprintf(stdout, "CAPTURE THREAD CREATE!\n");
  if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return NULL;
  }
  pthread_cleanup_push(cleaner, pd);
  if(pcap_compile(pd, &fcode, bpfFilter, 1, maskp) < 0) { // TODO corretta mask
    printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
  } else {
    if(pcap_setfilter(pd, &fcode) < 0) {
      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
    }
  }

  pcap_loop(pd, -1, process_arp, NULL);
  pthread_cleanup_pop(0);
  return 0;
}

/**
 * MAIN THREAD
 * Retrieve informations about the net, loads and store the Hash Table and create inject and capture threads
 */
int main (int argc, char** argv) {
  pthread_t inj_thread,
    capt_thread;
  char* net;
  char* mask;
  struct in_addr ipaddr;
  struct in_addr maskaddr;
  int c, rc;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dumpFilename = NULL;

  while ((c = getopt(argc, argv, "i:r:f:t:")) != -1) {
    switch (c) {
      case 'i':
        device = optarg;
        break;
      case 'r':
        rpt = atoi(optarg);
	      break;
      case 'f':
        dumpFilename = optarg;
        break;
      case 't':
        interval = atoi(optarg);
        break;
      default:
	print_usage();
	exit(-1);
    }

  }

  // If no device is selected, use default
  if (device == NULL) {
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(-1);
    }
  }
  fprintf(stdout, "Arping device %s\n", device);

  /* obtain ip e mask */
  if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
    netp = 0;
    maskp = 0;
  }

  // set MAC and IP
  getMacIp(src_mac_addr, &src_ip_addr, device);
  // convert in dot notation
  printf("Ip: %s\n", inet_ntoa(src_ip_addr));
  // convert mask in dot notation
  maskaddr.s_addr = maskp;
  mask = inet_ntoa(maskaddr);
  printf("Mask: %s\n",mask);


  printf("Mac: %s\n",macToStr(src_mac_addr));
  fprintf(stdout, "* * * * * * * * * *\n");

  /* load the hash table from file */
  initializeScanTime();
  if(dumpFilename == NULL) loadHt(DEFAULT_DUMP_FILENAME);
  else loadHt(dumpFilename);
  // Add sender MAC to the Hash Table, because the compiled filter accept
  // only ARP reply.
  insert(src_mac_addr, src_ip_addr, time(NULL));

  // Create threads
  pthread_create(&capt_thread, NULL, capture_arp, NULL);
  pthread_create(&inj_thread, NULL, inject_arp, NULL);

  pthread_join(inj_thread, NULL);
  sleep(timeout);
  rc = pthread_cancel(capt_thread);
  pthread_join(capt_thread, NULL);
  if(rc) printf("failed to close\n");
  // store the hash table into file
  if(dumpFilename == NULL) storeHt(DEFAULT_DUMP_FILENAME);
  else storeHt(dumpFilename);
  logDevices();
  destroyHt();
  printf("exiting...\n");
  return 0;
}
