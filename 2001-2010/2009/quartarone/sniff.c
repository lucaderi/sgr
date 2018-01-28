#include "intestazione.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <pwd.h>
#include "pkt_analyzer.h"

#define MAX_BUF_IN 9
#define MAX_DEVICE_LEN 5
#define Description(NAME,DESC) printf("name: %s ---- description: %s\n",NAME    ,DESC)
#define FINISH exit(EXIT_FAILURE)
#define MAX_NUMBER_BYTE_CAP 65935
#define OpenOffLine(file) if((pcap_in=pcap_open_offline(file,error))==NULL){ \
   fprintf(stderr,"error pcap_open_offline: %s\n",errbuf); FINISH; }
#define ChecARG if(strlen(optarg)==0){help(); FINISH;}


struct param_th{
   pcap_dumper_t *file_dump;
   pcap_t *pcap_in;
}param_th;


void changeUser() {
   struct passwd *pw = NULL; 
   if(getuid() == 0) {
      /* We're root */
      char *user;
      pw = getpwnam(user = "nobody");
      if(pw != NULL) {
	 if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0))
	    fprintf(stderr,"Unable to change user to %s [%d:%d]: sticking with root\n",user, pw->pw_uid, pw->pw_gid);
	 else
	    fprintf(stderr,"Changed user to %s\n", user);
	 }
   }
}


void thread(struct param_th *p){
   pcap_loop(p->pcap_in,-1,loopPacket,(u_char*)p->file_dump);
}

void processPacket(pcap_t *pcap_in, pcap_dumper_t *file_dump){
   pthread_t pth_id;
   struct param_th param;
   int err;
   fprintf(stderr,"processP\n");
   param.file_dump=file_dump;
   param.pcap_in=pcap_in;
   if((err=pthread_create(&pth_id,NULL,thread,&param))!=0)
      return;
   while((getchar())!='q'); 
}


static void help(){
   
   printf("   -i   capture interface\n   -f   file read\n   -w   file write\n \
	 -p   promiscus mode\n\n");
   printf("sniff -p -i <interface> -f <file>.pcap -w <fileWrite>\n");
   exit(0);
}

int main(int argc, char* argv[]){
   char errbuf[PCAP_ERRBUF_SIZE], device[MAX_DEVICE_LEN], fileRead[MAX_BUF_IN],
	fileWrite[MAX_BUF_IN];
   int promisc, live;
   extern int linkLayer;
   pcap_t *pcap_in;
   pcap_dumper_t *file_dump;
   FILE *file;
   bpf_u_int32 netmask, netp;
   char c;
  
   live=0;
   promisc=0;
   fileRead[0]='\0';
   fileWrite[0]='\0';
   device[0]='\0';
   if(getuid()!=0){
      fprintf(stderr,"You must be root\n");
      FINISH;
   }
   while((c=getopt(argc,argv,"hvpi:f:w:"))!=-1){
	 switch(c){
	    case 'h': help(); break;
	    case 'p': promisc=1; break;
	    case 'i': {ChecARG;
			 sscanf(strncpy(device,optarg,MAX_DEVICE_LEN),"%s",device);
		      }break;
	    case 'f': {ChecARG;
			 sscanf(strncpy(fileRead,optarg,MAX_BUF_IN),"%s",fileRead);
		      }break;
	    case 'w': {ChecARG;
			 sscanf(strncpy(fileWrite,optarg,MAX_BUF_IN),"%s",fileWrite);
		      }break;
	    default: {
			fprintf(stderr,"Parametro non valido\n");
			FINISH;
		     }
	 }
   }

   if((strlen(fileRead))==0){
      /* se non viene inserita un interfaccia, viene aperta la prima disposbibile */
      if(strlen(device)==0){
	 if(!(strncpy(device,(pcap_lookupdev(errbuf)),MAX_DEVICE_LEN))){
	    fprintf(stderr,"error lookupdev: %s\n",errbuf);
	    FINISH;
	 }
      }
      else{
	 if(pcap_lookupnet(device,&netp,&netmask,errbuf)==-1){
	    fprintf(stderr,"error pcap_lookupdev: %s\n",errbuf);
	    FINISH;
	 }
      }
      /* la cattura live viene attivata solo nel caso in cui non viene specifciato
       * nessun file da cui leggere */
      if(!(pcap_in=pcap_open_live(device,MAX_NUMBER_BYTE_CAP,promisc,0,errbuf))){
	 fprintf(stderr,"error pcap_open_live: %s\n",errbuf);
	 FINISH;
      }
   }
   else{
      if((pcap_in=pcap_open_offline(fileRead,errbuf))==NULL){
	 fprintf(stderr,"error pcap_open_offline: %s\n",errbuf);
	 FINISH;
      }
   }
   linkLayer=pcap_datalink(pcap_in);
   if((strlen(fileWrite))>0){
      if((file_dump=pcap_dump_open(pcap_in,fileWrite))==NULL){
	 fprintf(stderr,"error pcap_dump_open: %s\n",pcap_geterr(pcap_in));
	 FINISH;
      }
   }
   changeUser(); 
   printf("Start sniffing on %s ,  enter q to stop\n",device);
   processPacket(pcap_in,file_dump);
   pcap_close(pcap_in);
   printf("Teminated\n");
}

