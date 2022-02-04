  #include <stdio.h>
  #include <string.h>
  #include <pcap.h>
  #include <stdlib.h>
  #include <netinet/in.h>
  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <signal.h>
  #include "md5_nDPI.h"
  
  //struttura che riassume tutte le informazioni da stampare 
  typedef struct _SSH{
    char ssh_protocol_client[100];
    int algorithms_length_client[10];
    char algorithms_client[2000];
    u_char fingerprint_client[16];
    char ip_source_client[INET_ADDRSTRLEN];
    char ip_dest_client[INET_ADDRSTRLEN];
    int port_source_client;
    int port_dest_client;
    char ssh_protocol_server[100];
    int algorithms_length_server[10];
    char algorithms_server[2000];
    u_char fingerprint_server[16];
    char ip_source_server[INET_ADDRSTRLEN];
    char ip_dest_server[INET_ADDRSTRLEN];
    int port_source_server;
    int port_dest_server;
    int completed;//flag che indica se sono arrivati tutti i pacchetti 
  }SSH;

  // array di struttura SSH
  SSH ssh[1024];
 
  //descrittore di pcap
  pcap_t *handle = NULL;
  
  // contatore per l'array SSH
  int ncount = 0;

  //Gestore segnali
  void gestore_int(int sig){
    pcap_breakloop(handle); //funzione thread-safe, interrompe 
  }


  /* Puntatori agli headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  /* Header lengths in bytes */
  int ethernet_header_length = 14;
  int ip_header_length;
  int tcp_header_length;
  int payload_length;
  int total_headers_size;

  /* struct header */
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;

  //legge e salva il payload del pacchetto che contiene il protocollo ssh usato
  void GetSSHProtocol(char *ssh_protocol){
    const u_char *temp_pointer = payload;
    int i = 0;
    while(i < payload_length){
      ssh_protocol[i] = temp_pointer[i];
      i++;
    }
  }
  
  //recupera dal payload la porzione degli algoritmi interessat compresi tra start e end 
  u_char* GetAlgo(int start, int end){
    const u_char *temp_pointer = payload;
    temp_pointer += start;
    char *algo = calloc(end,sizeof(char));
    int i = 0;
    while(i < (end-start)){
      algo[i] = temp_pointer[i];
      i++;
    }
    return algo;
  }
  
  //recupera e salva le le comunicazione per identificare la comunizazione
  void IP_TCP_info(char *sourceIP, char *destIP, int *sourcePort, int *destPort){
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    *(sourcePort) = ntohs(tcpHeader->source);
    *(destPort) = ntohs(tcpHeader->dest);
  }
  
  //stampa le fingerprint delle comunicazioni
  void PrintInfo(){
    for(int i=0;i<ncount;i++){
      if(ssh[i].completed>=2){
        printf("[-] Client SSH_MSG_KEXINT detected ");
        printf("[%s:%d -> %s:%d]\n",ssh[i].ip_source_client,ssh[i].port_source_client,ssh[i].ip_dest_client,ssh[i].port_dest_client);
        printf("[-] SSH Protocol: %s",ssh[i].ssh_protocol_client);
        printf("[-] hassh: ");
        for(int j=0; j<16; j++)
          printf("%02x", ssh[i].fingerprint_client[j]);
        printf("\n[-] hassh Algorithms: %s\n",ssh[i].algorithms_client);
        printf("\n[-] Server SSH_MSG_KEXINT detected ");
        printf("[%s:%d -> %s:%d]\n",ssh[i].ip_source_server,ssh[i].port_source_server,ssh[i].ip_dest_server,ssh[i].port_dest_server);
        printf("[-] SSH Protocol: %s",ssh[i].ssh_protocol_server);
        printf("[-] hassh: ");
        for(int j=0; j<16; j++)
          printf("%02x", ssh[i].fingerprint_server[j]);
        printf("\n[-] hassh Algorithms: %s\n\n",ssh[i].algorithms_server);
        for(int i=0;i<80;i++)
          printf("-");
        printf("\n\n");
      }
    }
  }
  
  //recupera l'indice della comunicazione in corso da completare altrimenti ne apre una nuova
  int GetPos(char *sourceIP, char *destIP, int sourcePort, int destPort){
    for(int i = 0; i < ncount; i++) {
      if(!strcmp(destIP,ssh[i].ip_source_client) && !strcmp(sourceIP,ssh[i].ip_dest_client) && destPort==ssh[i].port_source_client && sourcePort==ssh[i].port_dest_client)
        return i;
      else if(!strcmp(destIP,ssh[i].ip_source_server) && !strcmp(sourceIP,ssh[i].ip_dest_server) && destPort==ssh[i].port_source_server && sourcePort==ssh[i].port_dest_server)
        return i;
    }
    ncount++;
    return ncount-1;
  }
  
  //calcola le lunghezze degli algoritmi nel pacchetto
  int GetLength(int start){
    u_char pl1 = *(payload + 0 + start);
    u_char pl2 = *(payload + 1 + start);
    u_char pl3 = *(payload + 2 + start);
    u_char pl4 = *(payload + 3 + start);
    u_char packet_length[20] = "";
    sprintf(packet_length,"-%x-%x-%x-%x-",pl1,pl2,pl3,pl4);
    int i = 0, j = 0; char temp[255] = "";
    while(packet_length[i]){
      if(packet_length[i]=='-' && packet_length[i+2]=='-'){
        temp[j] = '0';
        temp[j+1] = packet_length[i+1];
        j+=2;
        i+=2;
      }
      else{
        temp[j] = packet_length[i+1];
        temp[j+1] = packet_length[i+2];
        j+=2;
        i+=3;
      }
    }
    int number = (int)strtol(temp,NULL,16);//conversione da hex ascii in integer
    return number;
  }
  
  //seleziona gli algoritmi da concatenare
  void Algorithms(char *str){
    int l1 = GetLength(22);//lunghezza del primo blocco di algoritmi
    if(l1<-1)return ;
    char *str1 = GetAlgo(26,26+l1);
    strcpy(str,str1);
    free(str1);
    int l2 = GetLength(26 + l1);//lunghezza del secondo blocco di algoritmi
    int l3 = GetLength(26 + l1 + l2 + 4);//lunghezza terzo blocco di algoritmi
    strcat(str,";");
    char *str2 = GetAlgo(26+l1 + 4 + l2 + 4,26+l1+ 4 + l2 + 4 + l3);
    strcat(str,str2);
    free(str2);
    int l4 = GetLength(26 + l1 + 4 + l2 +4 + l3);//lunghezza quarto blocco di algoritmi
    int l5 = GetLength(26 + l1+4+l2+4+l3+4+l4);//lunghezza quinto blocco di algoritmi
    strcat(str,";");
    char *str3 = GetAlgo(26+l1+4+l2+4+l3+4+l4+4,26+l1+4+l2+4+l3+4+l4+4+l5);
    strcat(str,str3);
    free(str3);
    int l6 = GetLength(26 + l1+4+l2+4+l3+4+l4+4+l5);//lunghezza sesto blocco di algortimi
    int l7 = GetLength(26 + l1+4+l2+4+l3+4+l4+4+l5+4+l6);//lunghezza settimo blocco di algoritmi
    strcat(str,";");
    char *str4 = GetAlgo(26+l1+4+l2+4+l3+4+l4+4+l5+4+l6+4,26+l1+4+l2+4+l3+4+l4+4+l5+4+l6+4+l7);
    strcat(str,str4);
    free(str4);
    int l8 = GetLength(26 + l1+4+l2+4+l3+4+l4+4+l5+4+l6+4+l7);
  }

  //gestore pacchetto
  void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
      printf("Not an IP packet. Skipping...\n\n");
      return;
    }

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
      printf("Not a TCP packet\n\n");
      return;
    }

    /* pointer to struct header */
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    /* Add the ethernet and ip header length to the start of the packet
      to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    /* Add up all the header sizes to find the payload offset */
    total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;

    payload_length = header->caplen -(ethernet_header_length + ip_header_length + tcp_header_length);

    if(payload_length == 0) return;

    payload = packet + total_headers_size;

    char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    int sourcePort, destPort;
    IP_TCP_info(sourceIP, destIP, &sourcePort, &destPort);
    
    if (payload_length > 7 && payload_length < 100 && memcmp(payload,"SSH-",4) == 0) {
      if(destPort == 22 || destPort == 2222){//client to server 
        int pos = GetPos(sourceIP, destIP, sourcePort, destPort);
        GetSSHProtocol(ssh[pos].ssh_protocol_client);
        strcpy(ssh[pos].ip_source_client,sourceIP);
        ssh[pos].port_source_client = sourcePort;
        strcpy(ssh[pos].ip_dest_client,destIP);
        ssh[pos].port_dest_client = destPort;
      }
      else {//server to client
        int pos = GetPos(sourceIP, destIP, sourcePort, destPort);
        GetSSHProtocol(ssh[pos].ssh_protocol_server);
        strcpy(ssh[pos].ip_source_server,sourceIP);
        ssh[pos].port_source_server = sourcePort;
        strcpy(ssh[pos].ip_dest_server,destIP);
        ssh[pos].port_dest_server = destPort;
      }
    }
    else if(payload_length > 300 && payload_length < 2000){//client to server
      u_int8_t msgcode = *(payload + 5);//decodifica del message code per identificare il tipo di pacchetto
      if(msgcode == 20){
        if(destPort == 22 || destPort == 2222){
          int pos = GetPos(sourceIP, destIP, sourcePort, destPort);
          Algorithms(ssh[pos].algorithms_client);
          MD5_CTX ctx;//calcolo fingerprint
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ssh[pos].algorithms_client, strlen(ssh[pos].algorithms_client));
          MD5Final(ssh[pos].fingerprint_client, &ctx);
          ssh[pos].completed++;
        }
        else {//server to client
          int pos = GetPos(sourceIP, destIP, sourcePort, destPort);
          Algorithms(ssh[pos].algorithms_server);
          MD5_CTX ctx;//calcolo fingerprint
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ssh[pos].algorithms_server, strlen(ssh[pos].algorithms_server));
          MD5Final(ssh[pos].fingerprint_server, &ctx);
          ssh[pos].completed++;
        }
      } 
    }
    return;
  }

  static void help() {
    printf("filter <device or pcap>\n");
    printf("Example: ./filter sample_ssh.pcap\n");
    exit(0);
  }


    
//Installazione signal handler
  void Signal(){
    struct sigaction s; 
    memset(&s,0,sizeof(s));
    s.sa_handler=gestore_int;
    if(sigaction(SIGINT,&s,NULL)==-1)
      perror("sigaction SIGINT"); 
    if(sigaction(SIGQUIT,&s,NULL)==-1)
      perror("sigaction SIGQUIT"); 
    if(sigaction(SIGTERM,&s,NULL)==-1)
      perror("sigaction SIGTERM");
  }


  int main(int argc, char **argv) {
    Signal();
    const char *dev = "lo";
    handle = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "port 22 or port 2222";
    bpf_u_int32 subnet_mask, ip;

    if(argc == 1)
      help();

    dev = argv[1];

    if(strstr(dev, ".pcap")) {
      handle = pcap_open_offline(dev, error_buffer);
      if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
      }
    } else {
      if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
      }

      handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
      if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
      }
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
      printf("Bad filter - %s\n", pcap_geterr(handle));
      return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
      printf("Error setting filter - %s\n", pcap_geterr(handle));
      return 2;
    }
    pcap_loop(handle,-1, my_packet_handler,NULL);
    pcap_close(handle);
    PrintInfo();
    return 0;
  }
