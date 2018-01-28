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

#include"Jpcap_sub.h"

#ifndef IP_RF
#define IP_RF 0x8000
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

/** analyze ip header **/
u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data){
  struct ip *ip_pkt;
  jbyteArray src_addr,dst_addr;
  u_short hdrlen;

#ifdef DEBUG
  puts("analyze ip");
#endif

  ip_pkt=(struct ip *)data;

  src_addr=(*env)->NewByteArray(env,4);
  dst_addr=(*env)->NewByteArray(env,4);
  (*env)->SetByteArrayRegion(env,src_addr,0,4,(char *)&ip_pkt->ip_src);
  (*env)->SetByteArrayRegion(env,dst_addr,0,4,(char *)&ip_pkt->ip_dst);

  // updated by Damien Daspit 5/7/01
  (*env)->CallVoidMethod(env,packet,setIPValueMID,
			     (jbyte)4,
			     (jbyte)(ip_pkt->ip_tos>>5),
				 (jboolean)(((ip_pkt->ip_tos&IPTOS_LOWDELAY)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((ip_pkt->ip_tos&IPTOS_THROUGHPUT)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((ip_pkt->ip_tos&IPTOS_RELIABILITY)>0)?JNI_TRUE:JNI_FALSE),
			     (jbyte)(ip_pkt->ip_tos&0x3),
				 (jboolean)(((ip_pkt->ip_off&IP_RF)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((ip_pkt->ip_off&IP_DF)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((ip_pkt->ip_off&IP_MF)>0)?JNI_TRUE:JNI_FALSE),
			     (jshort)(ntohs(ip_pkt->ip_off)&IP_OFFMASK),
			     (jshort)ntohs(ip_pkt->ip_len),
			     (jint)ntohs(ip_pkt->ip_id),
			     (jshort)ip_pkt->ip_ttl,
			     (jshort)ip_pkt->ip_p,
			     src_addr,dst_addr);
  // ********************************
  DeleteLocalRef(src_addr);
  DeleteLocalRef(dst_addr);

  // added by Damien Daspit 5/7/01
  hdrlen = ip_pkt->ip_hl<<2;
  if(hdrlen > IPv4HDRLEN){
    jbyteArray dataArray=(*env)->NewByteArray(env,hdrlen-IPv4HDRLEN);
    (*env)->SetByteArrayRegion(env,dataArray,0,hdrlen-IPv4HDRLEN,data+IPv4HDRLEN);
    (*env)->CallVoidMethod(env,packet,setIPv4OptionMID,dataArray);
    DeleteLocalRef(dataArray);
  }
  // *****************************

  return ip_pkt->ip_hl<<2;
}

void set_ip(JNIEnv *env,jobject packet,char *pointer){
  struct ip *ip=(struct ip *)pointer;

  jbyteArray src=(*env)->CallObjectMethod(env,packet,getSourceAddressMID);
  jbyteArray dst=(*env)->CallObjectMethod(env,packet,getDestinationAddressMID);

  ip->ip_v=4;
  ip->ip_hl=IPv4HDRLEN>>2;
  ip->ip_id=htons((jshort)GetIntField(IPPacket,packet,"ident"));
  ip->ip_off=((GetBooleanField(IPPacket,packet,"rsv_frag")?IP_RF:0)+
    (GetBooleanField(IPPacket,packet,"dont_frag")?IP_DF:0)+
    (GetBooleanField(IPPacket,packet,"more_frag")?IP_MF:0)+
    htons(GetShortField(IPPacket,packet,"offset")));
  ip->ip_ttl=(u_char)GetShortField(IPPacket,packet,"hop_limit");
  // updated by Damien Daspit 5/7/01
  ip->ip_tos=(GetByteField(IPPacket,packet,"priority")<<5)+
    (GetByteField(IPPacket,packet,"rsv_tos"))+
    (GetBooleanField(IPPacket,packet,"d_flag")?IPTOS_LOWDELAY:0)+
    (GetBooleanField(IPPacket,packet,"t_flag")?IPTOS_THROUGHPUT:0)+
    (GetBooleanField(IPPacket,packet,"r_flag")?IPTOS_RELIABILITY:0);
  // *******************************
  (*env)->GetByteArrayRegion(env,src,0,4,(char *)&ip->ip_src);
  (*env)->GetByteArrayRegion(env,dst,0,4,(char *)&ip->ip_dst);

  DeleteLocalRef(src);
  DeleteLocalRef(dst);
}
