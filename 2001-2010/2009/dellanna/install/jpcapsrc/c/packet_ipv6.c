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

#ifdef INET6
#ifndef WIN32
#define COMPAT_RFC2292
#include<sys/socket.h>
#else
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
typedef int            pid_t;
#define IPPROTO_HOPOPTS        0 /* IPv6 Hop-by-Hop options */
#define IPPROTO_IPV6          41 /* IPv6 header */
#define IPPROTO_ROUTING       43 /* IPv6 Routing header */
#define IPPROTO_FRAGMENT      44 /* IPv6 fragmentation header */
#define IPPROTO_ESP           50 /* encapsulating security payload */
#define IPPROTO_AH            51 /* authentication header */
#define IPPROTO_ICMPV6        58 /* ICMPv6 */
#define IPPROTO_NONE          59 /* IPv6 no next header */
#define IPPROTO_DSTOPTS       60 /* IPv6 Destination options */
#include<ws2tcpip.h>
//#include<tpipv6.h> //no longer needed for .Net
#endif
#include<netinet/ip6.h>

struct ah {
	u_int8_t	ah_nxt;		/* Next Header */
	u_int8_t	ah_len;		/* Length of data, in 32bit */
	u_int16_t	ah_reserve;	/* Reserved for future use */
	u_int32_t	ah_spi;		/* Security parameter index */
	/* variable size, 32bit bound*/	/* Authentication data */
};

struct newah {
	u_int8_t	ah_nxt;		/* Next Header */
	u_int8_t	ah_len;		/* Length of data + 1, in 32bit */
	u_int16_t	ah_reserve;	/* Reserved for future use */
	u_int32_t	ah_spi;		/* Security parameter index */
	u_int32_t	ah_seq;		/* Sequence number field */
	/* variable size, 32bit bound*/	/* Authentication data */
};
#endif

#ifdef INET6
u_short analyze_ipv6(JNIEnv *env,jobject packet,u_char *data){
  struct ip6_hdr *v6_pkt;
  jbyte proto;
  jbyteArray src_addr,dst_addr;
  int hlen=0;
  
#ifdef DEBUG
  puts("analyze ipv6");
#endif

	v6_pkt=(struct ip6_hdr *)data;

	src_addr=(*env)->NewByteArray(env,16);
	dst_addr=(*env)->NewByteArray(env,16);
	(*env)->SetByteArrayRegion(env,src_addr,0,16,
	                           (char *)&v6_pkt->ip6_src);
	(*env)->SetByteArrayRegion(env,dst_addr,0,16,
	                           (char *)&v6_pkt->ip6_dst);

	(*env)->CallVoidMethod(env,packet,setIPv6ValueMID,
	                       (jbyte)6,
	                       //class
	                       (jbyte)(v6_pkt->ip6_flow&0x0ff00000)>>20,
	                       (jint)ntohl(v6_pkt->ip6_flow&0x000fffff),
	                       (jshort)ntohs(v6_pkt->ip6_plen),
	                       (jbyte)v6_pkt->ip6_nxt,
	                       (jshort)v6_pkt->ip6_hlim,
	                       src_addr,
	                       dst_addr);

	DeleteLocalRef(src_addr);
	DeleteLocalRef(dst_addr);

	hlen+=40;
	proto=v6_pkt->ip6_nxt;
	data+=hlen;

	while (proto==IPPROTO_HOPOPTS || proto==IPPROTO_DSTOPTS ||
	        proto==IPPROTO_ROUTING || proto==IPPROTO_AH ||
	        proto==IPPROTO_FRAGMENT) {

			jobject opt_hdr=AllocObject(IPv6Option);
			struct ip6_ext *ip6_ext=(struct ip6_ext *)data;
			struct ip6_frag *ip6_frag;
			struct ip6_rthdr *ip6_rthdr;
			struct newah *ah;
			jbyteArray opt_data;
			int i;
			jobjectArray addrs;
			unsigned char *p;

			(*env)->CallVoidMethod(env,opt_hdr,setV6OptValueMID,
			                       (jbyte)proto,(jbyte)ip6_ext->ip6e_nxt,
			                       (jbyte)ip6_ext->ip6e_len);

			switch (proto) {
					case IPPROTO_HOPOPTS: /* Hop-by-Hop */
					case IPPROTO_DSTOPTS: /* Destionation */
						opt_data=(*env)->NewByteArray(env,ip6_ext->ip6e_len);
						(*env)->SetByteArrayRegion(env,opt_data,0,ip6_ext->ip6e_len,
						                           (jbyte *)(ip6_ext+2));
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptOptionMID,
						                       opt_data);
						DeleteLocalRef(opt_data);
						hlen+=(ip6_ext->ip6e_len+1)<<3;
						data+=(ip6_ext->ip6e_len+1)<<3;

						break;

					case IPPROTO_ROUTING: // patch from Wang
						ip6_rthdr=(struct ip6_rthdr *)ip6_ext;//construct a Type0 Routing Header

						addrs=(*env)->NewObjectArray(env,(jsize)(ip6_rthdr->ip6r_len>>1),FindClass("[B"),NULL);
						
						for (i=0,p=data+8;i<(ip6_rthdr->ip6r_len>>1);i++,data+=16) {
							opt_data=(*env)->NewByteArray(env,16);
							(*env)->SetByteArrayRegion(env,opt_data,0,16,(jbyte *)p);
							(*env)->SetObjectArrayElement(env,addrs,i,opt_data);
							DeleteLocalRef(opt_data);
						}

						(*env)->CallVoidMethod(env,opt_hdr,setV6OptRoutingMID,
						                       (jbyte)ip6_rthdr->ip6r_type,
						                       (jbyte)ip6_rthdr->ip6r_segleft,
						                       addrs);

						DeleteLocalRef(addrs);
						hlen+=(ip6_ext->ip6e_len+1)<<3;
						data+=(ip6_ext->ip6e_len+1)<<3;
						break;
					case IPPROTO_FRAGMENT:
						ip6_frag=(struct ip6_frag *)ip6_ext;
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptFragmentMID,
						                       (jshort)ntohs(ip6_frag->ip6f_offlg&
						                                     IP6F_OFF_MASK),
						                       (jboolean)(((ip6_frag->ip6f_offlg&IP6F_MORE_FRAG)>0)?JNI_TRUE:JNI_FALSE),
						                       (jint)ntohl(ip6_frag->ip6f_ident));
						hlen+=8;
						data+=8;
						break;
					case IPPROTO_AH:
						ah=(struct newah *)ip6_ext;
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptAHMID,
						                       (jint)ntohl(ah->ah_spi),
						                       (jint)ntohl(ah->ah_seq));
						opt_data=(*env)->NewByteArray(env,ah->ah_len);
						(*env)->SetByteArrayRegion(env,opt_data,
						                           0,ah->ah_len,
						                           (jbyte *)(ah+8));
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptOptionMID,
						                       opt_data);
						DeleteLocalRef(opt_data);

						hlen+=(ah->ah_len+2)<<2;
						data+=(ah->ah_len+2)<<2;
						break;
				}

			(*env)->CallVoidMethod(env,packet,addIPv6OptHdrMID,opt_hdr);
			DeleteLocalRef(opt_hdr);
			proto = ip6_ext->ip6e_nxt;
		}
	return hlen;
}

void set_ipv6(JNIEnv *env,jobject packet,char *pointer){
	struct ip6_hdr *v6_pkt=(struct ip6_hdr *)pointer;
	
	jbyteArray src=(*env)->CallObjectMethod(env,packet,getSourceAddressMID);
	jbyteArray dst=(*env)->CallObjectMethod(env,packet,getDestinationAddressMID);

	v6_pkt->ip6_flow=0;

	//set version
	v6_pkt->ip6_vfc=0x60;

	//set source and dest addr
	(*env)->GetByteArrayRegion(env,src,0,16,(char *)&v6_pkt->ip6_src);
	(*env)->GetByteArrayRegion(env,dst,0,16,(char *)&v6_pkt->ip6_dst);
	DeleteLocalRef(src);
	DeleteLocalRef(dst);

	//set class
	v6_pkt->ip6_flow|=htonl(((GetByteField(IPPacket,packet,"priority")<<20) | GetIntField(IPPacket,packet,"flow_label")) & 0x0fffffff);

	//payload length is set in JpcapSender.set_packet();

	//next hdr
	v6_pkt->ip6_nxt=GetShortField(IPPacket,packet,"protocol");

	v6_pkt->ip6_hlim=GetShortField(IPPacket,packet,"hop_limit");

	//XXX need to put IPv6Options, too.
}

#endif
