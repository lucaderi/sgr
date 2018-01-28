#include<jni.h>
#include<pcap.h>

//#define DEBUG
//#define BSD_BUG

#include<sys/types.h>
#ifndef WIN32
#include<sys/param.h>
#include<sys/socket.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<netdb.h>
#else
#include<winsock2.h>
#include<ws2tcpip.h>
//#include<packet32.h>
#endif
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<string.h>

#include"Jpcap_sub.h"
#include"Jpcap_ether.h"

#ifdef INET6
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
#endif

#pragma export on
#include"jpcap_JpcapSender.h"
#pragma export reset

#ifdef WIN32
//LPADAPTER adapters[MAX_NUMBER_OF_INSTANCE];
SOCKET sockRaw=INVALID_SOCKET;
#else
int soc_num=-1;
#endif

unsigned short in_cksum(unsigned short *addr,int len);
int set_packet(JNIEnv *env, jobject packet,char *pointer,int include_datalink);

int set_ether(JNIEnv *env,jobject packet,char *pointer);
void set_ip(JNIEnv *env,jobject packet,char *pointer);
void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data,struct ip *ip);
void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data,struct ip *ip);
int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
int set_arp(JNIEnv *env,jobject packet,u_char *pointer);
#ifdef INET6
void set_ipv6(JNIEnv *env,jobject packet,char *pointer);
#endif

jclass JpcapSender=NULL;

int getJpcapSenderID(JNIEnv *env, jobject obj){
  if(JpcapSender==NULL)
    GlobalClassRef(JpcapSender,"jpcap/JpcapSender");
  return GetIntField(JpcapSender,obj,"ID");
}


/*
 * Class:     jpcap_JpcapSender
 * Method:    nativeOpenDevice
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT jstring JNICALL Java_jpcap_JpcapSender_nativeOpenDevice
(JNIEnv *env, jobject obj, jstring device){
	char *dev;
	jint id;
	
	set_Java_env(env);
	
	id=getJpcapSenderID(env,obj);


	jni_envs[id]=env;

	if(pcds[id]!=NULL){
		return NewString("Another Jpcap instance is being used.");
	}
	if(device==NULL){
		return NewString("Please specify device name.");
	}
	dev=(char *)GetStringChars(device);

	pcds[id]=pcap_open_live(dev,65535,0,1000,pcap_errbuf[id]);

	ReleaseStringChars(device,dev);

	if(pcds[id]==NULL) return NewString(pcap_errbuf[id]);

	return NULL;
}


/**
Open raw socket for sending IP packet
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeOpenRawSocket(JNIEnv *env,jobject obj){
  int on=1;
#ifdef WIN32
  WSADATA wsaData;
#endif

  set_Java_env(env);

#ifdef WIN32
  if(sockRaw!=INVALID_SOCKET){
#else
  if(soc_num>=0){
#endif
	  Throw(IOException,"Raw Socket is already opened.");
    return;
  }

#ifdef WIN32
  // Start Winsock up
  if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0) {
      Throw(IOException,"Failed to find Winsock 2.1 or better.");
      return;
  }

  sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, 0);
  if (sockRaw == INVALID_SOCKET) {
//	  printf("%d\n",WSAGetLastError());
      Throw(IOException,"Failed to create raw socket.");
      return;
  }
  setsockopt(sockRaw,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on));
#else
  if((soc_num=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0){
    Throw(IOException,"can't initialize socket");
    return;
  }
  setsockopt(soc_num,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on));
#endif

//#endif
}




/**
Send packet via pcap
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeSendPacket(JNIEnv *env,jobject obj,jobject packet){
  char buf[MAX_PACKET_SIZE];
  int length;
  int id=getJpcapSenderID(env,obj);

  if(pcds[id]==NULL){
	Throw(IOException,"Another JpcapSender instance is being used.");
	return;
  }

#ifdef DEBUG
  puts("set packet.");
#endif
  length=set_packet(env,packet,buf,-1);
  if(length<60){ //include Ethernet trailer
	  memset(buf+length,0,60-length+1);
	  length=60;
  }

#ifdef DEBUG
  puts("send packet.");
#endif
  if(pcap_sendpacket(pcds[id],buf,length)<0){
		Throw(IOException,pcap_errbuf[id]);
    return;
  }
}

/**
Send IP Packet via Raw socket
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeSendPacketViaRawSocket(JNIEnv *env,jobject obj,jobject packet)
{
  char buf[MAX_PACKET_SIZE];
  struct ip *ip=(struct ip *)buf;
  int length;
  struct sockaddr_in dest;

  if(!IsInstanceOf(packet,IPPacket)){
    Throw(IOException,"seinding non-IP packet is not supported");
    return;
  }
#ifdef WIN32
  if(sockRaw==INVALID_SOCKET){
    Throw(IOException,"socket not initialized yet");
    return;
  }
#else
  if(soc_num<0){
    Throw(IOException,"socket not initialized yet");
    return;
  }
#endif
  length=set_packet(env,packet,buf,0);

  //set destination address
  memset((char *)&dest,0,sizeof(dest));
  dest.sin_family=AF_INET;
  //bug fix by Peter Martin
  dest.sin_addr=ip->ip_dst;

#ifdef WIN32
	if(sendto(sockRaw,buf,length,0,(struct sockaddr *)&dest,sizeof(dest))<0){
#else
	if(sendto(soc_num,buf,length,0,(struct sockaddr *)&dest,sizeof(dest))<0){
#endif
		Throw(IOException,"sendto error");
    return;
  }
}

int set_packet(JNIEnv *env, jobject packet,char *pointer,int include_datalink){
  int length=0,dthlen=0;
  jbyteArray data;

  if(include_datalink){
	dthlen=set_ether(env,packet,pointer);
    pointer+=dthlen;
  }

  data=GetObjectField(Packet,packet,"[B","data");
  if(data==NULL){
	length=0;
  }else{
	length=(*env)->GetArrayLength(env,data);
  }

  if(IsInstanceOf(packet,IPPacket)){
	struct ip *ip=(struct ip *)pointer;
#ifdef INET6
	struct ip6_hdr *ipv6=(struct ip6_hdr *)pointer;
#endif
	int ver=GetByteField(IPPacket,packet,"version");

	if(ver==4){
		set_ip(env,packet,pointer);
		///XXX: This does not consider IP options
		length+=IPv4HDRLEN;
		pointer+=IPv4HDRLEN;
	}else{
#ifdef INET6
		set_ipv6(env,packet,pointer);
		///XXX: This does not consider IP options
		length+=40;
		pointer+=40;
#else
		Throw(IOException,"only IPv4 packet is supported");
		return 0;
#endif
	}
	if(IsInstanceOf(packet,TCPPacket)){
		length+=TCPHDRLEN;
		if(ver==4){
			ip->ip_p=IPPROTO_TCP;
			ip->ip_len=length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_TCP;
			ipv6->ip6_plen=length;
#endif
		}

		set_tcp(env,packet,pointer,data,ip);
	  }else if(IsInstanceOf(packet,UDPPacket)){
		length+=UDPHDRLEN;
		if(ver==4){
			ip->ip_p=IPPROTO_UDP;
			ip->ip_len=length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_UDP;
			ipv6->ip6_plen=length;
#endif
		}

		set_udp(env,packet,pointer,data,ip);
	  }else if(IsInstanceOf(packet,ICMPPacket)){
		length+=set_icmp(env,packet,pointer,data);
		if(ver==4){
			ip->ip_p=IPPROTO_ICMP;
			ip->ip_len=length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_ICMP;
			ipv6->ip6_plen=length;
#endif
		}
	}else{
		if(ver==4){
			ip->ip_p=(unsigned char)GetShortField(IPPacket,packet,"protocol");
			ip->ip_len=length;
			//bug fix by Brad Dillmn
			(*env)->GetByteArrayRegion(env,data,0,
					   length-IPv4HDRLEN,pointer);
#ifdef INET6
		}else{
			//ipv6->ip6_nxt=IPPROTO_ICMP; -> already done in set_ipv6()
			ipv6->ip6_plen=length;
			(*env)->GetByteArrayRegion(env,data,0,
					   length-40,pointer);
#endif
		}
	}

	  if(ver==4){
#ifndef BSD_BUG
		ip->ip_len=htons(ip->ip_len);
		ip->ip_off=htons(ip->ip_off);
#endif
		ip->ip_sum=0;
		ip->ip_sum=in_cksum((u_short *)ip,20);
	}
  }else if(IsInstanceOf(packet,ARPPacket)){
	length+=set_arp(env,packet,pointer);
  }else{ //unknown type
		(*env)->GetByteArrayRegion(env,data,0,
					   length,pointer);
  }

  return length+dthlen;
}

unsigned short in_cksum(unsigned short *data,int size){
        unsigned long sum = 0;

        while(size > 1){
                sum += *(data++);
                size -= 2;
        }

        if(size > 0) sum += (*data) & 0xff00;
        sum = (sum & 0xffff) + (sum >> 16);

        return ((~(unsigned short)((sum >> 16) + (sum & 0xffff))));
}

unsigned short in_cksum2(struct ip *ip,u_short len,unsigned short *data,int size){
        unsigned long sum = 0;
		u_short *p=(u_short *)&ip->ip_src;

		/*sum+=ip->ip_src.S_un.S_un_w.s_w1;
		sum+=ip->ip_src.S_un.S_un_w.s_w2;
		sum+=ip->ip_dst.S_un.S_un_w.s_w1;
		sum+=ip->ip_dst.S_un.S_un_w.s_w2;*/
		sum+=*(p++);
		sum+=*(p++);
		sum+=*(p++);
		sum+=*(p++);
		sum+=htons((u_short)(ip->ip_p&0x00ff));
		sum+=len;

        while(size > 1){
                sum += *(data++);
                size -= 2;
        }

		if(size > 0){
			sum += *(unsigned char *)data;
		}
        sum = (sum & 0xffff) + (sum >> 16);

        return ((~(unsigned short)((sum >> 16) + (sum & 0xffff))));
}



/**
Close Live Capture Device
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeCloseDevice(JNIEnv *env,jobject obj)
{
  int id=getJpcapSenderID(env,obj);
  if(pcds[id]!=NULL) pcap_close(pcds[id]);
  pcds[id]=NULL;
}

JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeCloseRawSocket(JNIEnv *env,jobject obj)
{
#ifdef WIN32
//  int id=getJpcapSenderID(env,obj);
//  PacketCloseAdapter(adapters[id]);
	closesocket(sockRaw);
  WSACleanup();
#else
  //bug fix by Peter Martin
  close(soc_num);
#endif
}
