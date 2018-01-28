#include<jni.h>
#include<pcap.h>

#ifndef WIN32
#include<sys/param.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<sys/socket.h>
#include<net/if.h>
#else
#include<winsock2.h>
#endif

#include<netinet/if_ether.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>

#include"Jpcap_sub.h"

/** analyze arp header **/
int analyze_arp(JNIEnv *env,jobject packet,u_char *data){
	/** XXX assume Ethernet ARP**/
  struct ether_arp *arp=(struct ether_arp *)data;
  jbyteArray sha,spa,tha,tpa;
  u_char hl,pl;

#ifdef DEBUG
  puts ("analyze arp");
#endif

  hl=arp->arp_hln;
  pl=arp->arp_pln;

  sha=(*env)->NewByteArray(env,hl);
  (*env)->SetByteArrayRegion(env,sha,0,hl,(char *)(data+sizeof(struct arphdr)));
  spa=(*env)->NewByteArray(env,pl);
  (*env)->SetByteArrayRegion(env,spa,0,pl,(char *)(data+sizeof(struct arphdr)+hl));
  tha=(*env)->NewByteArray(env,hl);
  (*env)->SetByteArrayRegion(env,tha,0,hl,(char *)(data+sizeof(struct arphdr)+hl+pl));
  tpa=(*env)->NewByteArray(env,pl);
  (*env)->SetByteArrayRegion(env,tpa,0,pl,(char *)(data+sizeof(struct arphdr)+hl+pl+hl));

  (*env)->CallVoidMethod(env,packet,setARPValueMID,
			     (jshort)ntohs(arp->arp_hrd),
			     (jshort)ntohs(arp->arp_pro),
			     (jshort)hl,(jshort)pl,
			     (jshort)ntohs(arp->arp_op),
			     sha,spa,tha,tpa);
  DeleteLocalRef(sha);
  DeleteLocalRef(spa);
  DeleteLocalRef(tha);
  DeleteLocalRef(tpa);

  return sizeof(struct arphdr)+hl*2+pl*2;
}

int set_arp(JNIEnv *env,jobject packet,u_char *pointer){
	/** XXX assume Ethernet ARP**/
  struct ether_arp *arp=(struct ether_arp *)pointer;

  arp->arp_hrd=htons(GetShortField(ARPPacket,packet,"hardtype"));
  arp->arp_pro=htons(GetShortField(ARPPacket,packet,"prototype"));
  arp->arp_op=htons(GetShortField(ARPPacket,packet,"operation"));
  arp->arp_hln=(u_char)GetShortField(ARPPacket,packet,"hlen");
  arp->arp_pln=(u_char)GetShortField(ARPPacket,packet,"plen");

  (*env)->GetByteArrayRegion(env,
	  GetObjectField(ARPPacket,packet,"[B","sender_hardaddr"),
	  0,arp->arp_hln,arp->arp_sha);
  (*env)->GetByteArrayRegion(env,
	  GetObjectField(ARPPacket,packet,"[B","sender_protoaddr"),
	  0,arp->arp_pln,arp->arp_spa);
  (*env)->GetByteArrayRegion(env,
	  GetObjectField(ARPPacket,packet,"[B","target_hardaddr"),
	  0,arp->arp_hln,arp->arp_tha);
  (*env)->GetByteArrayRegion(env,
	  GetObjectField(ARPPacket,packet,"[B","target_protoaddr"),
	  0,arp->arp_pln,arp->arp_tpa);

  return sizeof(struct ether_arp);
}
