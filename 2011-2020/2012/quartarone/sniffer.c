#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#include "pktUtils.h"
#include "sniffer.h"
#include <arpa/inet.h>
#include <netinet/ether.h>




void pkt_process(u_char *args, const struct pcap_pkthdr* header, const u_char* ptr_pkt){
  
  u_char *pkt;
  u_short type;

  pkt = (u_char*) ptr_pkt;
  header_len = get_header_len(datalink);
  
  //wrong pkt
  if(header_len > header->caplen)
    return ; 

  switch(datalink){
    case DLT_EN10MB:{
      struct ether_header *hdr_eth  = (struct ether_header *)pkt;
      type = ntohs(hdr_eth->ether_type);
#ifdef DEBUG
      printf("########################################\n");
      printf("MAC src: %s\n",ether_ntoa((struct ether_addr*)hdr_eth->ether_shost));
      printf("MAC dst: %s\n",ether_ntoa((struct ether_addr*)hdr_eth->ether_dhost));
#endif
    }break;
    
  }
  
 
  if(header_len == header->caplen){
    //gestione errore
    return;
  }
  // LAYER 3
  pkt += header_len;
  pkt_size = header_len + header->caplen;

  switch(type){
    case ETHERTYPE_IP :
      ip_analyzer(pkt,header);
      break;
  
  }




}





int main(){
  const char *dtlStr;
  char errbuf[ERR_BUF_SIZE];
   pthread_t tid[FLOW_BUF_NO];
  int i;

  pcap_t *handle;



 if(!( handle = pcap_open_live("em1",CAPSIZE, PROISC, TIMEOUT, errbuf))){
  fprintf(stderr,"Error in device");
  return -1;
 }

 datalink = pcap_datalink(handle);
 if( !(dtlStr = pcap_datalink_val_to_name(datalink))){
   fprintf(stderr,"Unsupported link layer for device %s\n","em1");
   return -1;
 }
 

 int buf_no = ( 1 << FLOW_BUF_NO);
 for(i=0; i< FLOW_BUF_NO; i++){
   flow_buffer[i].first = 1;
   flow_buffer[i].last = 0;
   flow_buffer[i].size=0;
//   if(pthread_create(&tid[i],NULL, th_processor,NULL)== NULL)
//     break;
  
 }

 pcap_loop(handle, 100 ,pkt_process, NULL);
 
 for(i=0; i<FLOW_BUF_NO; i++){
  printf("size: %d) -- %d \n",i,  flow_buffer[i].size);
 }

}
