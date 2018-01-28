#include<jni.h>
#include<pcap.h>

#ifndef WIN32
#include<sys/param.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#else
#include<winsock2.h>
#endif

#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>

#include"Jpcap_sub.h"

u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data);
void set_ip(JNIEnv *env,jobject packet,char *pointer);

/** analyze icmp header **/
void analyze_icmp(JNIEnv *env,jobject packet,u_char *data,u_short clen){
  struct icmp *icmp_pkt=(struct icmp *)data;
  jobject ippacket;
  jbyteArray addr;

#ifdef DEBUG
  puts("analyze icmp");
  printf("type:%d,code:%d\n",icmp_pkt->icmp_type,icmp_pkt->icmp_code);
#endif

  (*env)->CallVoidMethod(env,packet,setICMPValueMID,
			     icmp_pkt->icmp_type,icmp_pkt->icmp_code,
			     icmp_pkt->icmp_cksum);
  
  if(icmp_pkt->icmp_type==ICMP_ECHOREPLY || /* echo reply */
	  icmp_pkt->icmp_type==ICMP_ECHO || /* echo */
	  icmp_pkt->icmp_type>ICMP_PARAMPROB){ /* parameter problem */
    (*env)->CallVoidMethod(env,packet,setICMPIDMID,
			       (jshort)icmp_pkt->icmp_id >> 8,
			       (jshort)icmp_pkt->icmp_seq >> 8 );
  }
  switch(icmp_pkt->icmp_type){
  case ICMP_REDIRECT: /* redirect */
    addr=(*env)->NewByteArray(env,4);
    (*env)->SetByteArrayRegion(env,addr,0,4,
				   (char *)&icmp_pkt->icmp_gwaddr);
    (*env)->CallVoidMethod(env,packet,setICMPRedirectIPMID,
			       addr);
    DeleteLocalRef(addr);
  case ICMP_UNREACH: /* unreachable */
    (*env)->SetShortField(env,packet,
			    (*env)->GetFieldID(env,ICMPPacket,
						   "mtu","S"),
			    (jshort)icmp_pkt->icmp_nextmtu);
  case ICMP_SOURCEQUENCH: /* source quench */
  case ICMP_TIMXCEED: /* time exceeded */
  case ICMP_PARAMPROB: /*parameter problem */
    if(clen<IPv4HDRLEN+16) break;
    ippacket=AllocObject(IPPacket);
    analyze_ip(env,ippacket,(u_char *)&icmp_pkt->icmp_ip);
    (*env)->SetObjectField(env,packet,
			    (*env)->GetFieldID(env,ICMPPacket,
						   "ippacket",
						   "Ljpcap/packet/IPPacket;"),
			    ippacket);
    DeleteLocalRef(ippacket);
	break; 
#ifdef icmp_num_addrs
  case ICMP_ROUTERADVERT: /* router advertisement */
    {
      jint prefs[icmp_pkt->icmp_num_addrs];
      jobjectArray addrArray=(*env)->NewObjectArray(env,
				(jsize)icmp_pkt->icmp_num_addrs,
							String,NULL);
      jintArray prefArray=(*env)->NewIntArray(env,
					      icmp_pkt->icmp_num_addrs);
      int i;
      
      for(i=0;i<icmp_pkt->icmp_num_addrs;i++){
	jstring addr_str=NewString((const char *)
	     inet_ntoa(*(struct in_addr *)(icmp_pkt->icmp_data+8+(i<<3))));
	prefs[i]=(int)(icmp_pkt->icmp_data+8+(i<<3)+4);
	(*env)->SetObjectArrayElement(env,addrArray,i,addr);
	DeleteLocalRef(addr_str);
      }
      (*env)->SetIntArrayRegion(env,prefArray,0,
				    (jsize)icmp_pkt->icmp_num_addrs,prefs);

      (*env)->CallVoidMethod(env,packet,setICMPRouterAdMID,
				 (jbyte)icmp_pkt->icmp_num_addrs,
				 (jbyte)icmp_pkt->icmp_wpa,
				 (jshort)icmp_pkt->icmp_lifetime,
				 addrArray,prefArray);

      DeleteLocalRef(addrArray);
      DeleteLocalRef(prefArray);
    }
    break;
#endif
  case ICMP_TSTAMP: case ICMP_TSTAMPREPLY: /* timestamp*/
    (*env)->CallVoidMethod(env,packet,setICMPTimestampMID,
			       (jint)icmp_pkt->icmp_otime,
			       (jint)icmp_pkt->icmp_rtime,
			       (jint)icmp_pkt->icmp_ttime);
    break;
  case ICMP_MASKREQ: case ICMP_MASKREPLY:   /* netmask*/
    (*env)->SetIntField(env,packet,
			    (*env)->GetFieldID(env,ICMPPacket,
						   "subnetmask","I"),
			    (jint)icmp_pkt->icmp_mask);
    break;
  }
}

int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data)
{
  struct icmp *icmp=(struct icmp *)pointer;
  jint length=0;
  jbyteArray addr;
  jobject ippacket;

  if(data!=NULL)
	  length=(*env)->GetArrayLength(env,data);

  icmp->icmp_type=GetByteField(ICMPPacket,packet,"type");
  icmp->icmp_code=GetByteField(ICMPPacket,packet,"code");
  
  switch(icmp->icmp_type){
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    icmp->icmp_id=htons((jshort)GetShortField(ICMPPacket,packet,"id"));
    icmp->icmp_seq=htons((jshort)GetShortField(ICMPPacket,packet,"seq"));
 	// updated by Damien Daspit 5/15/01
	if(data!=NULL)
		(*env)->GetByteArrayRegion(env,data,0,length,(u_char *)icmp->icmp_data);
	icmp->icmp_cksum=0;
	icmp->icmp_cksum=in_cksum((u_short *)icmp,8+length);
	return 8; //no need to include data length
    break;
  case ICMP_REDIRECT: /* redirect */
    addr=(*env)->CallObjectMethod(env,packet,getICMPRedirectIPMID);
    (*env)->GetByteArrayRegion(env,addr,0,4,(char *)&icmp->icmp_gwaddr);
    DeleteLocalRef(addr);
  case ICMP_UNREACH: /* unreachable */
  case ICMP_SOURCEQUENCH: /* source quench */
  case ICMP_TIMXCEED: /* time exceeded */
  case ICMP_PARAMPROB: /*parameter problem */
    ippacket=GetObjectField(ICMPPacket,packet,"Ljpcap/packet/IPPacket;","ippacket");
	if(ippacket!=NULL){
		set_ip(env,ippacket,(u_char *)&icmp->icmp_ip);
	    DeleteLocalRef(ippacket);
	}
	icmp->icmp_cksum=0;
	icmp->icmp_cksum=in_cksum((u_short *)icmp,12+(ippacket==NULL?0:20));
	return 12+(ippacket==NULL?0:20)-length; //exclude data field
	break; 
  case ICMP_TSTAMP: case ICMP_TSTAMPREPLY: /* timestamp*/
    icmp->icmp_id=htons((jshort)GetShortField(ICMPPacket,packet,"id"));
    icmp->icmp_seq=htons((jshort)GetShortField(ICMPPacket,packet,"seq"));
	icmp->icmp_otime=htonl((jint)GetIntField(ICMPPacket,packet,"orig_timestamp"));
	icmp->icmp_rtime=htonl((jint)GetIntField(ICMPPacket,packet,"recv_timestamp"));
	icmp->icmp_ttime=htonl((jint)GetIntField(ICMPPacket,packet,"trans_timestamp"));
	icmp->icmp_cksum=0;
	icmp->icmp_cksum=in_cksum((u_short *)icmp,20);
    return 20-length; //exclude data field
    break;
  case ICMP_MASKREQ: case ICMP_MASKREPLY:   /* netmask*/
    icmp->icmp_id=htons((jshort)GetShortField(ICMPPacket,packet,"id"));
    icmp->icmp_seq=htons((jshort)GetShortField(ICMPPacket,packet,"seq"));
	icmp->icmp_mask=htonl((jint)GetIntField(ICMPPacket,packet,"subnetmask"));
	icmp->icmp_cksum=0;
	icmp->icmp_cksum=in_cksum((u_short *)icmp,12);
	return 12-length; //exclude data field
    break;
  default:
	return 0;
  }
}
