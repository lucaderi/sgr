/**
* @author Biancucci Francesco 545063
* @file main.c
* @brief arpscan with mac-name association and new connection monitoring
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netdb.h>

#include <pcap.h>
#include <math.h>

#include "defines.h"
#include "hasht.h"
#include "hasht_DB.h"

//network params
typedef struct _params_t {
    uint32_t startip;
    uint32_t endip;
    uint32_t mask;
}_params_t;

pcap_t* handler;
volatile sig_atomic_t contsignal = 1;

sigset_t sigmask;

//sig handler
static void *sig_thread(void *arg){
    int   sig;
    while(contsignal){
        int s = sigwait(&sigmask, &sig);
        if(s != 0){
          errno = s;
          perror("sigwait");
          pthread_exit(NULL);
        }
        if(sig == SIGINT || sig == SIGTERM || sig == SIGQUIT){
          contsignal = 0;
          alarm(1);
        }
    }

    return NULL;
}

void printUsage(char* s){
  fprintf(stderr, "Usage: %s -i <Interface> [-t <Timeout>] [-n <Number of loops>] [-v]\n", s);
  fprintf(stderr, "-t: LAN probing timeout (defualt 30s) \n");
  fprintf(stderr, "-n: number of probing loops (by default it will stop only with an external interrupt)\n");
  fprintf(stderr, "-v: lets you know the hardware brand name\n");
}

//conversion from integer to string, integer under form of dottted notation
char* dottedtostring(uint32_t dotted) {
  uint32_t conv = ntohl(dotted);
  char *_ip = (char *) calloc(16, sizeof(char));
  sprintf(_ip, "%d.%d.%d.%d", (conv >> 24) & 0xFF, (conv >> 16) & 0xFF, (conv >> 8) & 0xFF, conv & 0xFF);
  return _ip;
}

uint8_t* uint_32touint_8(uint32_t i32, uint8_t* dot){
  for(int i=0;i<IPV4LEN;i++){
    dot[i] = i32>>(i*8) & 0xFF;
  }
  return dot;
}

int toslash(uint32_t i32){
  uint8_t dot[IPV4LEN];
  uint_32touint_8(i32, dot);
  int inc=0;
  for(int i=0;i<IPV4LEN;i++){
    for(int j=0; j<8; j++){
      1 & (dot[i] >> 1u) ? inc++ : inc;
    }
  }
  return inc;
}
/**
* @fn exist_interface
* @☺brief checks if the input interface is a valid interface
* @returns 1 on success, -1 on failure
* @param s Input string
*/
int exist_interface(char* s){
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs, *temp;
  CHECK_ERR(pcap_findalldevs(&devs, error), "pcap_findalldevs");

  for(temp=devs; temp; temp=temp->next){
        if(!strcmp(temp->name, s)){
          pcap_freealldevs(devs);
          return 1;
        }
    }
    pcap_freealldevs(devs);
    errno=EINVAL;
    return -1;

}

void wakeup(int signum){
  /*do nothing*/
}

void terminate_process(int signum){
   pcap_breakloop(handler);
}

void functionA(){
    alarm(3);
    signal(SIGALRM, terminate_process);
}
/**
* @fn gethostparam
* @brief retrieves host mac and ip
*/
int gethostparam(uint8_t* mac, uint32_t* ip, char* interface){
  struct ifreq ifr;
  size_t len=strlen(interface);
  if (len<sizeof(ifr.ifr_name)) {
      memcpy(&ifr.ifr_name, interface, len);
      ifr.ifr_name[len]=0;
  } else {
      return -1;
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd==-1) return -1;

  // Obtain the source IP address and saves it into the ifr structure (works only with AF_INET addresses)
  if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
      close(fd);
      return -1;
  }
  struct sockaddr_in* sourceip = (struct sockaddr_in*)&ifr.ifr_addr;
  *ip = sourceip->sin_addr.s_addr;
  // Obtain the source MAC address
  if (ioctl(fd, SIOCGIFHWADDR, &ifr)==-1) {
      close(fd);
      return -1;
  }
  //check if it's an ether type interface
  if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
      close(fd);
      return -1;
  }
   memcpy(mac, ifr.ifr_hwaddr.sa_data, MACLEN);
   close(fd);
   return 1;
}

//prints the packet
void printpkt(hash_t* hasht, int verbose, hash_DB* hdb){
  int dimlist=0, appdim;;
  device** list = get_list_device(hasht, &dimlist);
  appdim=dimlist;
  for(int freeindex = 0; freeindex<dimlist; freeindex++){
    for(int k=0; k<MACLEN;k++){
      printf("%02X", list[freeindex]->mac[k]);
      if(k<MACLEN-1) printf(":");
    }
    if(verbose){
      if(list[freeindex]->nome) printf(" %s", list[freeindex]->nome);
      else{
        OUI_t* elem = find_OUI(hdb, list[freeindex]->mac);
        if(elem) printf(" %s", elem->nome);
        find_device(hasht, list[freeindex]->ip, list[freeindex]->mac, elem->nome);
      }

    }
    printf(" at ");
    for(int k=0; k<IPV4LEN; k++){
      printf("%d", list[freeindex]->ip[k]);
      if(k<IPV4LEN-1) printf(".");
    }
    if(list[freeindex]->new)
      printf(" First time seen\n");
    if(!list[freeindex]->new && (!list[freeindex]->disconnected || list[freeindex]->disconnected==-1)) printf(" Alive\n");
    if(list[freeindex]->disconnected>0 && list[freeindex]->disconnected<=1){
      printf(" No response\n");
      appdim--;
    }
    if(list[freeindex]->disconnected>1){
      printf(" No response, going to remove\n");
      appdim--;
      //rimuovo dalla lista
      delete_device(hasht, list[freeindex]->ip, list[freeindex]->mac);
    }
    free(list[freeindex]);
  }
  free(list);
  printf("\ndone (%d host alive) ", appdim);
}

//build ARP packet and sends it
int buildPkt(uint8_t* mac, uint32_t hostip, uint32_t destip){
  if(hostip == destip) return 1;
  struct ether_header header;
  header.ether_type=htons(ETH_P_ARP);
  memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

  // Construct ARP request (except for MAC and IP addresses).
  struct ether_arp req;
  req.arp_hrd=htons(ARPHRD_ETHER);
  req.arp_pro=htons(ETH_P_IP);
  req.arp_hln=ETHER_ADDR_LEN;
  req.arp_pln=sizeof(in_addr_t);
  req.arp_op=htons(ARPOP_REQUEST);
  memset(&req.arp_tha,0,sizeof(req.arp_tha));

  memcpy(&req.arp_tpa,&destip,sizeof(req.arp_tpa));

  memcpy(&req.arp_spa,&hostip,sizeof(req.arp_spa));

  memcpy(header.ether_shost,mac,sizeof(header.ether_shost));
  memcpy(&req.arp_sha,mac,sizeof(req.arp_sha));

  // Combine the Ethernet header and ARP request into a contiguous block.
  unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
  memcpy(frame,&header,sizeof(struct ether_header));
  memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

  /*Send a message*/
    if (pcap_inject(handler, frame, sizeof(frame)) == -1) {
      pcap_perror(handler, 0);
      pcap_close(handler);
      return -1;

    }
  return 1;
}

//creates a bpf filter and sets it
char* create_set_filter(char* filternoip, uint32_t iphost){
  char* dotret = dottedtostring(iphost);
  int lenf = strlen(filternoip);
  int lendot = strlen(dotret);
  char* filter = calloc(1, lenf + lendot +1);
  CHECK_NULL(filter, calloc);
  strcpy(filter, filternoip);
  strcat(filter, dotret);
  filter[lenf+lendot]=0;
  free(dotret);
  return filter;
}

//callback for the pcap loop
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct ether_arp* resp;
  hash_t* hash = (hash_t*) user;
  if(h->caplen<h->len) fprintf(stderr, "%s\n", "capture length is not the same as expected packet length");
  resp = (struct ether_arp *)(bytes+ETH_HEADERLEN_V2); /* Point to the ARP header */
  /* If is Ethernet and IPv4, print packet contents */
  if ((resp->arp_hrd) == htons(ARPHRD_ETHER) && (resp->arp_pro) == htons(ETH_P_IP))
    insert_device(hash, resp->arp_spa, resp->arp_sha);
}

int main(int argc, char* argv[]){
  int arg, verbose=0, tout=TIMEOUT, loopsnumber=0, loopindex=0, chunks=1;
  char *filternoip = "arp[6:2] = 2 and dst host ", *interface = NULL, *filter = NULL;
  hash_DB* hdb = NULL;
  struct bpf_program bpf;

  //retrieves mask and source ip
  bpf_u_int32 mask; // network mask
  bpf_u_int32 ip; // network ip
  uint8_t mac[MACLEN];
  uint8_t ipdot[IPV4LEN];

  uint32_t iphost;
  _params_t params;

  struct pcap_pkthdr pkthdr;
  const unsigned char *packet=NULL;
  hash_t* hasht;
  pthread_t sig_handler;


  while((arg = getopt(argc, argv, ":i:t:n:v:h")) != -1) {
    switch (arg) {
      case 'i':
        interface = optarg;
      break;
      case 't':
        tout = atoi(optarg);
      break;
      case 'n':
        loopsnumber = atoi(optarg);
      break;
      case 'v':
      //no params arg, reads the first value of the optstring
      break;
      case 'h':
        printUsage(argv[0]);
        exit(EXIT_SUCCESS);
      break;
      case ':':
      //first value of the optstring, it means i had -v
        verbose=1;
      break;
      default:
        printUsage(argv[0]);
        exit(EXIT_SUCCESS);
      break;

    }

  }
  CHECK_NULL(interface, Interface is null);
  //sighandler mask
  CHECK_ERR(sigemptyset(&sigmask), "sigemptyset");
  CHECK_ERR(sigaddset(&sigmask, SIGQUIT), "sigaddset");
  CHECK_ERR(sigaddset(&sigmask, SIGTERM), "sigaddset");
  CHECK_ERR(sigaddset(&sigmask, SIGINT), "sigaddset");
  CHECK_ZERO(pthread_sigmask(SIG_SETMASK, &sigmask, NULL), "pthread_sigmask");

  //sighandler thread
  CHECK_ZERO(pthread_create(&sig_handler, NULL, &sig_thread, &params), "pthread_create");

  CHECK_ERR(exist_interface(interface), Invalid interface);
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0]='\0';
  /*snaplen = double the size of ARP pkt*/
  handler = pcap_open_live(interface,96,0,0,pcap_errbuf);
  if (pcap_errbuf[0] != '\0') {
      fprintf(stderr, "%s\n", pcap_errbuf);
  }
  CHECK_NULL(handler, pcap_errbuf);


  /* get mask & ip */
  CHECK_ERR(pcap_lookupnet(interface, &ip, &mask, pcap_errbuf), "couldn't gat mask or ip");


  //compute first net ip and last net ip
  params.startip = ip;
  params.endip = ip | ~mask;
  params.mask = mask;
  int nhost = ntohl(params.endip) - ntohl(params.startip) + 1;
  hasht = hash_create_dev(ceil(nhost*1.3));
  //retrieve host mac  and ip addr
  CHECK_ERR(gethostparam(mac, &iphost, interface), Invalid mac address);
  char* dotted = dottedtostring(ip);
  printf("Starting arpscan for %s/%d\n", dotted, toslash(mask));
  free(dotted);
  uint8_t dot[IPV4LEN];
  uint_32touint_8(iphost, dot);

  insertself_device(hasht, dot, mac);


  /*set up the filter for scanning the right packet*/
  filter = create_set_filter(filternoip, iphost);
  CHECK_NULL(filter, create_set_filter);
  CHECK_ERR(pcap_compile(handler ,&bpf, filter, 0, ip), "couldn't compile filter");
  CHECK_ERR(pcap_setfilter(handler , &bpf), "Couldn't install filter");
  if(nhost>MAXHOST) {
    chunks=nhost>>8;
    (nhost & 0xFF) == 0 ? chunks : chunks++;
    nhost=MAXHOST;
  }
  if(!loopsnumber) loopindex=-1;
  //reads the db file and stores the associations in the hashtable
  if(verbose){
    FILE *fd;
    fd=fopen("EtherOUI.txt", "r+");
    if(fd==NULL){
      exit(EXIT_FAILURE);
    }
    char * line = NULL;
    char mac[21], nome[20];
    size_t len = 0;
    ssize_t read;
    int i = 0;

    while ((read = getline(&line, &len, fd)) != -1)
      i++;
    fseek(fd, 0, SEEK_SET);
    hdb = hash_create_DB(ceil(i*1.3));

    while ((read = getline(&line, &len, fd)) != -1) {
      if(*line != '#'){
        sscanf(line, "%s %s", mac, nome);
        insert_OUI(hdb, mac, nome);
      }
    }
    fclose(fd);
  }
  //loop for sending-receiving ARP packets
  while((loopindex < loopsnumber) && contsignal){
    uint32_t ipdest = params.startip;
    //chunk division for the scan
    for(int j=0;j<chunks;j++){
        for(int i=0;i<nhost; i++){
          CHECK_ERR(buildPkt(mac, iphost, ipdest), "");
          CHECK_ERR(buildPkt(mac, iphost, ipdest), "");
          ipdest = ipdest+htonl(1);
        }
        functionA();
        if((pcap_loop(handler, -1, callback, (u_char*) hasht)) == -1){
          fprintf(stderr, "Error getting the packet: %s\n", pcap_errbuf);
        }
      ipdest = ipdest+htonl(1);
    }
    if(loopsnumber)loopindex++;

    /*operazioni*/
    printpkt(hasht, verbose, hdb);

    printf("scanned: %d host\n\n", nhost);



    if((loopindex < loopsnumber) && contsignal){
      alarm(tout);
      signal(SIGALRM, wakeup);
      pause();
    }else if(loopindex>=loopsnumber)
      pthread_kill(sig_handler, SIGINT);
  }
  //free all the resources
  pcap_freecode(&bpf);
  pcap_close(handler);
  free(filter);
  hash_destroy_dev(hasht);
  if(hdb)  hash_destroy_DB(hdb);
  pthread_join(sig_handler, NULL);
  return 0;
}
