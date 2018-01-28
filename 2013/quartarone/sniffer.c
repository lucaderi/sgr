#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
 
#include "pktUtils.h"
#include "sniffer.h"
#include "rrdstats.h"
#include "data.h"
#include <arpa/inet.h>
#include <netinet/ether.h>

#define DEBUG
//


void print_mac(u_char *mac){
  int i;
  for(i =0; i<6; i++)
    printf("%02x",mac[i]);
  printf("\n");
}


void *th_flow_worker(void *args){
  flow_table_t *tab;
  flow_buffer_t *buf;
  pkt_rec_t *pkt_dec;
  flow_info_t info;
  flow_t *cur, *new;
  int wbase;
  int wsize;
  int index;
  #ifdef DEAD_LINE
  int step =0;
  #endif

  worker_args_t *warg = (worker_args_t *)args;
  tab = warg->f_tab;
  buf = warg->f_buf;
  wbase = warg->wbase;
  wsize = warg->wsize;

  while(1){
    pkt_dec = get_pkt(buf);
    if(pkt_dec){
      index = (pkt_dec->hash % wsize) + wbase;

      pthread_spin_lock(&tab[index].lock);
      get_flow_info(tab[index].flow,pkt_dec, &info);
      if(info.dir > 0 ){
        update_flow(info.flow,pkt_dec,info.dir);
        pthread_spin_unlock(&tab[index].lock);
      }else{
        new = make_flow(pkt_dec);
        add_flow(new, &tab[index]);
        pthread_spin_unlock(&tab[index].lock);
      }

/*      pthread_spin_lock(&tab[index].lock);
      cur = get_flow(tab[index].flow,pkt_dec);
      if(cur){
        update_flow(cur,pkt_dec,pkt_dec->inOut);
        pthread_spin_unlock(&tab[index].lock);
      }else{
          cur = make_flow(pkt_dec);
          add_flow(cur, &tab[index]);
          pthread_spin_unlock(&tab[index].lock);
      }
*/
    }else{
      usleep(SLEEP_TIME);
     //   break;
    }
  }
//  stop = 1;
}

void *th_collector(void *args){
  graveyard_t *grave;
  flow_table_t *tab;
#ifdef DEAD_LINE
  int step =0;
#endif
  grave = new_graveyard(FREE_LIST_SIZE);

  tab = (flow_table_t *)args;

  while(1){
    sleep(FLOW_COLLECTOR_INTERVAL);
    flow_collector(grave, tab);
//    printf("collector executed\n");
 /*
#ifdef DEAD_LINE
    step += FLOW_COLLECTOR_INTERVAL+30;
    if(step >= DEAD_LINE){
      stop=1;
      break;
    }
#endif
*/
  }
}

void th_dispatcher(u_char *args, const struct pcap_pkthdr* header, const u_char* ptr_pkt){
  u_char *pkt;
  u_short type;
  data_collector_t *collector;
  int datalink;
  int pkt_size;
  u_char *mac_addr;
  int header_len;
  enum flow_dir inOut;
  dispatcher_args_t *disp_args;
  disp_args = (dispatcher_args_t *)args;

  datalink = disp_args->datalink;
  mac_addr = disp_args->mac_addr;
  pkt = (u_char*) ptr_pkt;
  header_len = get_header_len(datalink);
  collector = get_data_collector();

  collector->last_up = header->ts.tv_sec;
  
  //wrong pkt
  if(header_len > header->caplen)
    return ; 
  
  switch(datalink){
    case DLT_EN10MB:{
      struct ether_header *eth_hdr  = (struct ether_header *)pkt;
      type = ntohs(eth_hdr->ether_type);
 //       print_mac(mac_addr);
      if( !bcmp(mac_addr, &(eth_hdr->ether_shost), 6)){
        data = &collector->data_out;
        inOut = OUT;

      }
      else{
        data = &collector->data_in;
        inOut = IN;
      }
        
#ifdef DEBUG
      printf("########################################\n");
      printf("IN-OUT: %d\n",inOut);
      printf("MAC src: %s\n",ether_ntoa((struct ether_addr*)eth_hdr->ether_shost));
      printf("MAC dst: %s\n",ether_ntoa((struct ether_addr*)eth_hdr->ether_dhost));
#endif
    }break;
    
  }
  if(header_len == header->caplen){
    //gestione errore
    return;
  }
  // LAYER 3
  pkt += header_len;
  pkt_size =header->len -  header_len ;
  data->bytes = pkt_size;
  data->pkts_no++;
  switch(type){
    case ETHERTYPE_IP :
      ip_analyzer(pkt,header,pkt_size, inOut);
      break;
    default :{
      data->not_ip++;
      data->not_ip_bytes = pkt_size;
    }
  
  }

//  if(stop)
//    pcap_breakloop(disp_args->handle);
}

void printTab(flow_table_t *tab){
  flow_t *f;
  int i;
  printf("________ TABLE __________\n");
  for(i=0; i<(1<<FLOW_HASH_TAB_SIZE); i++){

      f = tab[i].flow;
      while(f){
        printf("row: %d\n",i);
        printFlow(f);
        f= f->next;
      }
  }
  printf("__________________________ %d:\n",i);
}

void changeUser() {
	struct passwd *pw = NULL;
	
	if(getuid() == 0)
	{
		/* We're root */
		char *user;
		
		pw = getpwnam(user = "nobody");
		
		if(pw != NULL) 
		{
			if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
				printf("Unable to change user to %s [%d: %d]: sticking with root\n", user, pw->pw_uid, pw->pw_gid);
			else
				printf("Program changed user to %s\n", user);
		}
	}
}



int get_mac_addr(char *dev_name, u_char *mac )
{
	struct ifreq ifr;
	int sock;
  int ok = 0;
	
	if (!dev_name || !mac)
		return -1;
	
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
		perror("socket");
		return -1;
  }
	strcpy(ifr.ifr_name, dev_name);	
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
		if (! (ifr.ifr_flags & IFF_LOOPBACK))
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
				ok = 1;
	
  if (close(sock) == EINTR)
		close(sock);
	if (ok){
    bcopy(ifr.ifr_hwaddr.sa_data, mac, 6);
 /*   int i;
    for(i =0; i<6; i++){
      printf("%02x",mac[i]);
    }
    printf("\n");
  */
		return 0;
  }
  return -1;
}

void usage(){
printf("usage: [-h] [-i <interface>] [-r <rrdfile>] [-p <pcap_file>]\n");
  printf("\t-h : this menu`\n");
	printf("\t-i <interface> : capture from specified device\n");
	printf("\t-r <rrdfile> : store statistics on specified file\n");
	printf("\t-p <pcap_file> : capture offline from specified file\n");

}



int main(int argc, char *argv[]){
  const char *dtlStr;
  char errbuf[ERR_BUF_SIZE];
  char *rrdfile;
  char *iface, opt;
  char *options = ":i:r:p:";
  char *fpcap;
  int rrdtool = 0;
  int datalink;
  char mac_addr[6];
  
  
  pthread_t tid_rrd, tid_collector;
  pthread_t tid[FLOW_BUF_NO];
  worker_args_t worker_args[FLOW_BUF_NO];
  dispatcher_args_t disp_args;
  flow_table_t *ftable;
  data_collector_t *datac;
  int id =0;
  int i;
  pcap_t *handle;
  fpcap = NULL;
  iface = NULL;
   
  while ((opt = getopt(argc, argv, options)) != -1)	{
		switch (opt) {
			case 'i':
			{
        int len = strlen(optarg);
        iface = (char *)malloc(sizeof(char)*len+1);
        strcpy(iface,optarg);
			}	break;
			case 'r':
			{
				int len = strlen(optarg);
        rrdfile = (char *)malloc(sizeof(char)*len+1);
        strcpy(rrdfile,optarg);
				rrdtool = 1;
			}break;
      case 'p':
      {
        int len = strlen(optarg);
        fpcap = (char *)malloc(len * sizeof(char));
        strcpy(fpcap,optarg);
      }break;
			case 'h':
			default:
				usage();
        return -1;
        
		}
	}
if((argc > optind) || ( !iface && !fpcap) ){
  usage();
  return -1;
}

 // Allocazione tabella dei flussi
 //ftable = calloc((1<<FLOW_HASH_TAB_SIZE),sizeof(flow_table_t));
 if( !(ftable = new_flow_table())){
   printf("flow initialization error\n");
   return -1;
 }
 printf("- flow table initializated\n");
 init_data();
 //data collector
 datac = get_data_collector();
 init_data();
 printf("- data collector ok\n");
 // controllo del flusso in/out non e` supportato
 get_mac_addr(iface,mac_addr);
 print_mac(mac_addr);
 if(!fpcap){
   if(!( handle = pcap_open_live(iface,CAPSIZE, PROISC, TIMEOUT, errbuf))){
      fprintf(stderr,"Error in device: %s\n",errbuf);
      return -1;
   }
 }else{
   if(! (handle = pcap_open_offline(fpcap,errbuf))){
      fprintf(stderr,"Error pcap offline: %s\n",errbuf);
      return -1;
   }
 }

 datalink = pcap_datalink(handle);
 if( !(dtlStr = pcap_datalink_val_to_name(datalink))){
   fprintf(stderr,"Unsupported link layer for device %s\n",iface);
   return -1;
 }
 // switch user
 changeUser();

 // RRDtool
 printf("- config rrdtool\n");
  if( rrdtool ){
  rrd_update_args_t rrd_args;
  create_rrd(rrdfile);
  rrd_args.in_rrdfile = rrdfile;
  rrd_args.out_rrdfile = NULL;
  if( pthread_create(&tid_rrd, NULL, thread_update_rrd, (void*)&rrd_args) <0 )
    printf("thread_update_rrd error\n");
  else
    printf("rrdtool support enabled\n");
 }

 for(i=0; i< FLOW_BUF_NO; i++){
   flow_buffer[i].first = 1;
   flow_buffer[i].last = 0;
   flow_buffer[i].size=0;
   worker_args[i].f_tab = ftable;
   worker_args[i].f_buf = &flow_buffer[i];
   worker_args[i].wsize = (1<<FLOW_HASH_TAB_SIZE) / FLOW_BUF_NO;
   worker_args[i].wbase = i * (1<<FLOW_HASH_TAB_SIZE) / FLOW_BUF_NO;
   if(pthread_create(&tid[i],NULL, th_flow_worker,(void *)&worker_args[i]) <0){
     printf("th_flow_worker error\n");
     return -1;
   }
   printf("th_flow_worker %d created\n",i);
  }
 
 if( pthread_create(&tid_collector,NULL, th_collector,(void*)ftable) <0){
   printf("th_collector error\n");
   return -1;
 }

 // passare nel modo corretto datalink al dispatcher 
 disp_args.datalink = datalink;
 disp_args.mac_addr = mac_addr;
 disp_args.handle = handle;
 
 pcap_loop(handle, 0 ,th_dispatcher, (u_char *)&disp_args);
 
 for(i=0; i<FLOW_BUF_NO; i++)
   pthread_join(tid[i],NULL);

  printTab(ftable);

 for(i=0; i<FLOW_BUF_NO; i++){
  printf("size: %d) -- %d \n",i,  flow_buffer[i].size);
 }
 

}
