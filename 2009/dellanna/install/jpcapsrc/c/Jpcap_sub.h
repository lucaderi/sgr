/* Comment out next line to enable IPv6 capture*/
#define INET6 1

/* Comment out next line if you get an error 
   "structure has no member name 'sa_lan" */
#define HAVE_SA_LEN

/* for debugging */
//#define DEBUG

#define MAX_NUMBER_OF_INSTANCE 255

#define IPv4HDRLEN 20
#define TCPHDRLEN 20
#define UDPHDRLEN 8
#define ICMPHDRLEN 8
#define MAX_PACKET_SIZE 1600

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#define AllocObject(cls)    (*env)->AllocObject(env,cls)
#define FindClass(cls)		(*env)->FindClass(env,cls)
#define DeleteLocalRef(ref) (*env)->DeleteLocalRef(env,ref)
#define GlobalClassRef(cls,str)\
     cls=FindClass(str);\
     cls=(*env)->NewGlobalRef(env,cls)
#define NewString(str)      (*env)->NewStringUTF(env,str)
#define GetStringChars(str) (*env)->GetStringUTFChars(env,str,0)
#define ReleaseStringChars(str,ary) (*env)->ReleaseStringUTFChars(env,str,ary)
#define IsInstanceOf(obj,cls) (*env)->IsInstanceOf(env,obj,cls)
#define Throw(cls,msg) (*env)->ThrowNew(env,cls,msg)
#define GetIntField(cls,obj,name)\
     (*env)->GetIntField(env,obj,(*env)->GetFieldID(env,cls,name,"I"))
#define GetByteField(cls,obj,name)\
     (*env)->GetByteField(env,obj,(*env)->GetFieldID(env,cls,name,"B"))
#define GetShortField(cls,obj,name)\
     (*env)->GetShortField(env,obj,(*env)->GetFieldID(env,cls,name,"S"))
#define GetLongField(cls,obj,name)\
     (*env)->GetLongField(env,obj,(*env)->GetFieldID(env,cls,name,"J"))
#define GetBooleanField(cls,obj,name)\
     ((*env)->GetBooleanField(env,obj,\
			      (*env)->GetFieldID(env,cls,name,"Z"))?1:0)
#define GetObjectField(cls,obj,type,name)\
     (*env)->GetObjectField(env,obj,(*env)->GetFieldID(env,cls,name,type))
#define GetStaticObjectField(cls,type,name)\
	 (*env)->GetStaticObjectField(env,cls,(*env)->GetStaticFieldID(env,cls,name,type))
#define YIELD()\
     (*env)->CallStaticVoidMethod(env,Thread,\
		(*env)->GetStaticMethodID(env,Thread,"yield","()V"));

extern pcap_t *pcds[MAX_NUMBER_OF_INSTANCE];
extern JNIEnv *jni_envs[MAX_NUMBER_OF_INSTANCE];
extern char pcap_errbuf[PCAP_ERRBUF_SIZE][MAX_NUMBER_OF_INSTANCE];

extern jclass JpcapHandler,Packet,DatalinkPacket,EthernetPacket,IPPacket,
       TCPPacket,UDPPacket,ICMPPacket,IPv6Option,ARPPacket,String,Thread;
extern jclass UnknownHostException,IOException;
extern jmethodID printlnMID,handleMID,setPacketValueMID,setDatalinkPacketMID,setPacketDataMID,
  setEthernetValueMID,setIPValueMID,setIPv4OptionMID,setIPv6ValueMID,addIPv6OptHdrMID,
  setTCPValueMID,setTCPOptionMID,setUDPValueMID,
  setICMPValueMID,setICMPIDMID,setICMPTimestampMID,setICMPRedirectIPMID,getICMPRedirectIPMID,
  setICMPRouterAdMID,setV6OptValueMID,setV6OptOptionMID,setV6OptFragmentMID,
  setV6OptRoutingMID,setV6OptAHMID,
  setARPValueMID,
  getSourceAddressMID,getDestinationAddressMID;

extern unsigned short in_cksum(unsigned short *addr,int len);
extern unsigned short in_cksum2(struct ip *ip,u_short len,unsigned short *data,int size);
extern void set_Java_env(JNIEnv *env);
