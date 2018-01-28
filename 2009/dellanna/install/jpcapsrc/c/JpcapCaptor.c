#ifdef WIN32
#include<winsock2.h>
#include<iphlpapi.h>
#endif /* for WIN32 */

#include<jni.h>
#include<pcap.h>

//#include<net/bpf.h>

#ifndef WIN32
#include<sys/param.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<errno.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#ifndef SIOCGIFCONF
#include<sys/sockio.h>
#endif
#ifndef SIOCGIFHWADDR
#include<ifaddrs.h>
#include<net/if_dl.h>
#endif
#endif

#include<netinet/in_systm.h>
#include<netinet/ip.h>

#include<string.h>

#include"Jpcap_sub.h"
#include"Jpcap_ether.h"

#ifdef INET6
#ifndef WIN32
#define COMPAT_RFC2292
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
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
//#include<tpipv6.h> //no longer needed for .Net VC
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
#endif
#endif

#pragma export on
#include"jpcap_JpcapCaptor.h"
#pragma export reset

const int offset_type[]={0,12,-1,-1,-1,-1,20,-1,-1,2,
#ifdef PCAP_FDDIPAD
			  19+PCAP_FDDIPAD,
#else
			  19,
#endif
			  6,-1,-1,5};

const int offset_data[]={4,14,-1,-1,-1,-1,22,-1,16,4,
#ifdef PCAP_FDDIPAD
			   21+PCAP_FDDIPAD,
#else
			   21,
#endif
			   8,0,24,24};

#define get_network_type(data,id) ntohs(*(u_short *)(data+offset_type[linktypes[id]]))

#define skip_datalink_header(data,id)  (data+offset_data[linktypes[id]])

#define datalink_hlen(id) offset_data[linktypes[id]]

#define UNKNOWN_PROTO 0xffff

pcap_t *pcds[MAX_NUMBER_OF_INSTANCE];
JNIEnv *jni_envs[MAX_NUMBER_OF_INSTANCE];
char pcap_errbuf[PCAP_ERRBUF_SIZE][MAX_NUMBER_OF_INSTANCE];

jclass Jpcap=NULL,JpcapHandler,Interface,IAddress,Packet,DatalinkPacket,EthernetPacket,
	IPPacket,TCPPacket,UDPPacket,ICMPPacket,IPv6Option,ARPPacket,String,Thread,
	UnknownHostException,IOException;

jmethodID deviceConstMID,addressConstMID,handleMID,setPacketValueMID,setDatalinkPacketMID,
  setPacketHeaderMID,setPacketDataMID,
  setEthernetValueMID,setIPValueMID,setIPv4OptionMID,setIPv6ValueMID,addIPv6OptHdrMID,
  setTCPValueMID,setTCPOptionMID,setUDPValueMID,
  setICMPValueMID,setICMPIDMID,setICMPTimestampMID,setICMPRedirectIPMID,getICMPRedirectIPMID,
  setICMPRouterAdMID,setV6OptValueMID,setV6OptOptionMID,setV6OptFragmentMID,
  setV6OptRoutingMID,setV6OptAHMID,
  setARPValueMID,
  getSourceAddressMID,getDestinationAddressMID;

jfieldID jpcapID;

int linktypes[MAX_NUMBER_OF_INSTANCE];
bpf_u_int32 netnums[MAX_NUMBER_OF_INSTANCE],netmasks[MAX_NUMBER_OF_INSTANCE];
jobject jpcap_handlers[MAX_NUMBER_OF_INSTANCE];
char pcap_errbuf[PCAP_ERRBUF_SIZE][MAX_NUMBER_OF_INSTANCE];

void set_info(JNIEnv *env,jobject obj,pcap_t *pcd);
void set_Java_env(JNIEnv *);
void get_packet(struct pcap_pkthdr,u_char *,jobject *,int);
void dispatcher_handler(u_char *,const struct pcap_pkthdr *,const u_char *);

struct ip_packet *getIP(char *payload);

u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data);
u_short analyze_tcp(JNIEnv *env,jobject packet,u_char *data);
void analyze_udp(JNIEnv *env,jobject packet,u_char *data);
void analyze_icmp(JNIEnv *env,jobject packet,u_char *data,u_short len);
#ifdef INET6
u_short analyze_ipv6(JNIEnv *env,jobject packet,u_char *data);
#endif
int analyze_arp(JNIEnv *env,jobject packet,u_char *data);
jobject analyze_datalink(JNIEnv *env,u_char *data,int linktype);


int getJpcapID(JNIEnv *env,jobject obj)
{
	return GetIntField(Jpcap,obj,"ID");
}

jbyteArray getAddressByteArray(JNIEnv *env,struct sockaddr *addr)
{
	jbyteArray array;
	if(addr==NULL) return NULL;

	switch(addr->sa_family){
		case AF_INET:
			array=(*env)->NewByteArray(env,4);
			(*env)->SetByteArrayRegion(env,array,0,4,(jbyte *)&((struct sockaddr_in *)addr)->sin_addr);
			break;
		case AF_INET6:
			array=(*env)->NewByteArray(env,16);
			(*env)->SetByteArrayRegion(env,array,0,16,(jbyte *)&((struct sockaddr_in6 *)addr)->sin6_addr);
			break;
		default:
			//printf("AF:%d\n",addr->sa_family);
			return NULL;
			break;
	}
	return array;
}

/**
Get Interface List
**/
JNIEXPORT jobjectArray JNICALL Java_jpcap_JpcapCaptor_getDeviceList
  (JNIEnv *env, jclass cl)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	pcap_t *tmp_pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i=0,j=0,k=0;
	jobjectArray devices=NULL;
	jobjectArray addresses=NULL;
	jobject device=NULL;
	jobject address=NULL;
	int linktype;
	jstring lname,ldesc;
#ifdef WIN32
    u_long size=0;
	PIP_INTERFACE_INFO pInfo = NULL;
	MIB_IFROW MibIfRow;
	char **devnames;
	char *p1,*p2,*p3;
#else
#ifdef SIOCGIFHWADDR // Linux
    int sd;
    struct ifreq ifr;
	u_char buf[6];
#else //FreeBSD
    struct ifaddrs *ifa, *ifa0;
    struct sockaddr_dl* dl;

    getifaddrs(&ifa0);
#endif
#endif

	Interface=FindClass("jpcap/NetworkInterface");
	deviceConstMID=(*env)->GetMethodID(env,Interface,"<init>","(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;[B[Ljpcap/NetworkInterfaceAddress;)V");
	IAddress=FindClass("jpcap/NetworkInterfaceAddress");
	addressConstMID=(*env)->GetMethodID(env,IAddress,"<init>","([B[B[B[B)V");

	(*env)->ExceptionDescribe(env);

	/* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

	//count # of devices
	for(i=0,d=alldevs;d;d=d->next,i++);

	//create array
	devices=(*env)->NewObjectArray(env,(jsize)i,Interface,NULL);

#ifdef WIN32
	//obtain necessary size
	GetInterfaceInfo(NULL, &size);
	//allocate memory
	pInfo = (PIP_INTERFACE_INFO) malloc (size);
	if(GetInterfaceInfo(pInfo, &size)!=NO_ERROR){
		Throw(IOException,"GetInterfaceInfo failed.");
		return NULL;
	}
#endif

	/* Set Interface data */
    for(i=0,d=alldevs;d;d=d->next)
    {
		jbyteArray mac=(*env)->NewByteArray(env,6);
		//set mac
#ifdef WIN32
		// compare the device names obtained from Pcap and from IP Helper
		// in order to identify MAC address
		// since device name differs in 9x and NT/XP, compare name
		// from the end (not sure if this works in every case. I hope it does..)
		p1=d->name;
		while(*p1!=0) p1++;  //find the end

		//convert wchar to char
		devnames=(char **)malloc(sizeof(char *)*pInfo->NumAdapters);
		for(j=0;j<pInfo->NumAdapters;j++){
			size=WideCharToMultiByte(0,0,pInfo->Adapter[j].Name,-1,NULL,0,NULL,NULL);
			devnames[j]=(char *)malloc(size);
			WideCharToMultiByte(0,0,pInfo->Adapter[j].Name,-1,devnames[j],size,NULL,NULL);
			//printf("%s\n",devnames[j]);
		}

		for(j=0;j<pInfo->NumAdapters;j++){
			p2=p1;
			p3=devnames[j];
			while(*p3!=0) p3++; //find the end
			k=0;
			//printf("%s,%s:%d\n",d->name,devnames[j],j);
			while(*p2==*p3){
				p2--; p3--; k++;
				//printf("%c,%c,%d\n",*p2,*p3,k);
			}
			if(k<30) continue;

			//found! set MAC address
			MibIfRow.dwIndex=pInfo->Adapter[j].Index;
			GetIfEntry(&MibIfRow);
			(*env)->SetByteArrayRegion(env,mac,0,MibIfRow.dwPhysAddrLen,MibIfRow.bPhysAddr);
		}

#else
#ifdef SIOCGIFHWADDR  //Linux
    /* make socket */
    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sd < 0) {
		Throw(IOException,"cannot open socket.");
        return NULL; // error: can't create socket.
    }

    /* set interface name (lo, eth0, eth1,..) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name,d->name, IFNAMSIZ);

    /* get a Get Interface Hardware Address */
    ioctl(sd, SIOCGIFHWADDR, &ifr);

    close(sd);

	(*env)->SetByteArrayRegion(env,mac,0,6,ifr.ifr_ifru.ifru_hwaddr.sa_data);
#else //FreeBSD
    for(ifa=ifa0;ifa;ifa=ifa->ifa_next){
        dl=(struct sockaddr_dl*)ifa->ifa_addr;
        if(dl->sdl_nlen>0 && strncmp(d->name,dl->sdl_data,dl->sdl_nlen)==0){
            (*env)->SetByteArrayRegion(env,mac,0,6,LLADDR(dl));
        }
    }
#endif
#endif

		//count # of addresses
		for(j=0,a=d->addresses;a;a=a->next)
			if(getAddressByteArray(env,a->addr)) j++;

		//create array of addresses
		addresses=(*env)->NewObjectArray(env,(jsize)j,IAddress,NULL);

		//set address data
		for(j=0,a=d->addresses;a;a=a->next)
		{
			jbyteArray addr=getAddressByteArray(env,a->addr);
			if(addr){
				address=(*env)->NewObject(env,IAddress,addressConstMID,
					addr,getAddressByteArray(env,a->netmask),
					getAddressByteArray(env,a->broadaddr),getAddressByteArray(env,a->dstaddr));
				(*env)->SetObjectArrayElement(env,addresses,j++,address);
			}
		}

		//get datalink name
		tmp_pcap=pcap_open_live(d->name,0,0,1000,errbuf);
		if(tmp_pcap!=NULL){
			linktype=pcap_datalink(tmp_pcap);
			lname=NewString(pcap_datalink_val_to_name(linktype));
			ldesc=NewString(pcap_datalink_val_to_description(linktype));
			pcap_close(tmp_pcap);
		}else{
			lname=NewString("Unknown");
			ldesc=NewString("Unknown");
		}

		device=(*env)->NewObject(env,Interface,deviceConstMID,NewString(d->name),
			NewString(d->description),(d->flags&PCAP_IF_LOOPBACK?JNI_TRUE:JNI_FALSE),lname,ldesc,mac,addresses);
		(*env)->SetObjectArrayElement(env,devices,i++,device);

		DeleteLocalRef(device);
		DeleteLocalRef(mac);
    }
    
    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

	(*env)->ExceptionDescribe(env);

#ifndef WIN32
#ifdef SIOCGIFHWADDR
#else
    freeifaddrs(ifa0);
#endif
#endif

	return devices;
}

/**
Open Device for Live Capture
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_nativeOpenLive(JNIEnv *env,jobject obj,jstring device,jint snaplen,
			  jint promisc,jint to_ms)
{
  char *dev;
  jint id;

  set_Java_env(env);

  id=getJpcapID(env,obj);

  if(pcds[id]!=NULL){
	return NewString("Another Jpcap instance is being used.");
  }

  jni_envs[id]=env;

  if(device==NULL){
    return NewString("Please specify device name.");
  }
  dev=(char *)GetStringChars(device);

  pcds[id]=pcap_open_live(dev,snaplen,promisc,to_ms,pcap_errbuf[id]);
  if(pcap_lookupnet(dev,&netnums[id],&netmasks[id],pcap_errbuf[id])==-1){
	netmasks[id] = 0; 
  }

  ReleaseStringChars(device,dev);

  if(pcds[id]==NULL) return NewString(pcap_errbuf[id]);

  //set_info(env,obj,pcds[id]);
  linktypes[id]=pcap_datalink(pcds[id]);
  return NULL;
}

/**
Open Dumped File
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_nativeOpenOffline(JNIEnv *env,jobject obj,jstring filename)
{
  char *file;
  jint id;
  
  set_Java_env(env);

  id=getJpcapID(env,obj);

  if(pcds[id]!=NULL){
	return NewString("Another Jpcap instance is being used.");
  }
  jni_envs[id]=env;

  file=(char *)GetStringChars(filename);

  pcds[id]=pcap_open_offline(file,pcap_errbuf[id]);

  ReleaseStringChars(filename,file);

  if(pcds[id]==NULL) return NewString(pcap_errbuf[id]);

  //set_info(env,obj,pcds[id]);
  linktypes[id]=pcap_datalink(pcds[id]);
  set_Java_env(env);
  return NULL;
}

/**
Close Live Capture Device
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_nativeClose(JNIEnv *env,jobject obj)
{
  int id=getJpcapID(env,obj);
  if(pcds[id]!=NULL) pcap_close(pcds[id]);
  pcds[id]=NULL;
}


/**
Process Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_JpcapCaptor_processPacket(JNIEnv *env,jobject obj,
			       jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_dispatch(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}

/**
Loop Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_JpcapCaptor_loopPacket(JNIEnv *env,jobject obj,
			    jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_loop(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}


/**
Get One Packet
**/
JNIEXPORT jobject JNICALL
Java_jpcap_JpcapCaptor_getPacket(JNIEnv *env,jobject obj)
{
  struct pcap_pkthdr *header;
  jobject packet;
  int id=getJpcapID(env,obj);
  u_char *data;
  int res;

  res=pcap_next_ex(pcds[id],&header,(const u_char **)&data);

  switch(res){
	  case 0: //timeout
		  return NULL;
	  case -1: //error
		  return NULL;
	  case -2:
		  return GetStaticObjectField(Packet,"Ljpcap/packet/Packet;","EOF");
  }
  
  jni_envs[id]=env;
  if(data==NULL) return NULL;
  get_packet(*header,data,&packet,id);
  return packet;
}

/*
 * Class:     jpcap_JpcapCaptor
 * Method:    dispatchPacket
 * Signature: (ILjpcap/PacketReceiver;)I
 */
/*JNIEXPORT jint JNICALL Java_jpcap_JpcapCaptor_dispatchPacket
(JNIEnv *env,jobject obj, jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_dispatch(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}*/


/*
 * Class:     jpcap_JpcapCaptor
 * Method:    setNonBlockingMode
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_jpcap_JpcapCaptor_setNonBlockingMode
(JNIEnv *env, jobject obj, jboolean non_blocking){
	jint id=getJpcapID(env,obj);
	pcap_setnonblock(pcds[id],non_blocking,pcap_errbuf[id]);
}

/*
 * Class:     jpcap_JpcapCaptor
 * Method:    isNonBlockinMode
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_jpcap_JpcapCaptor_isNonBlockinMode
(JNIEnv *env, jobject obj){
	jint id=getJpcapID(env,obj);
	int nonblocking=pcap_getnonblock(pcds[id],pcap_errbuf[id]);
	return (nonblocking!=0?JNI_TRUE:JNI_FALSE);
}


/**
Set Filter
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_setFilter(JNIEnv *env,jobject obj,jstring condition,
			   jboolean opt)
{
  char *cdt=(char *)GetStringChars(condition);
  struct bpf_program program;
  int id=getJpcapID(env,obj);
  char *err=NULL;

  if(pcap_compile(pcds[id],&program,cdt,(opt==JNI_TRUE?-1:0),netmasks[id])!=0){
    err = pcap_geterr(pcds[id]);
    if (err == NULL)
      err = "pcap_compile failed";
  } else if(pcap_setfilter(pcds[id],&program)!=0){
    err = pcap_geterr(pcds[id]);
    if (err == NULL)
      err = "pcap_setfilter failed";
  }

  ReleaseStringChars(condition,cdt);


  if (err != NULL) {
    char buf[2048];
#ifdef WIN32
	strcpy_s(buf, 2048,"Error occurred while compiling or setting filter: ");
    strncat_s(buf, 2048, err, _TRUNCATE);
#else
	strcpy(buf, "Error occurred while compiling or setting filter: ");
    strncat(buf, err, 2047-strlen(buf));
#endif
	buf[2047] = 0;
    Throw(IOException, buf);
  }
}


/**
Break loop
**/
JNIEXPORT void JNICALL Java_jpcap_JpcapCaptor_breakLoop
(JNIEnv *env, jobject obj)
{
  int id=getJpcapID(env,obj);

  pcap_breakloop(pcds[id]);
}


/**
Update Statistics
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_updateStat(JNIEnv *env,jobject obj)
{
  struct pcap_stat stat;
  jfieldID fid;
  int id=getJpcapID(env,obj);

  pcap_stats(pcds[id],&stat);

  fid=(*env)->GetFieldID(env,Jpcap,"received_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_recv);
  fid=(*env)->GetFieldID(env,Jpcap,"dropped_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_drop);
}

/**
Get Error Message
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_getErrorMessage(JNIEnv *env,jobject obj)
{
  int id=getJpcapID(env,obj);
  return NewString(pcap_errbuf[id]);
}

/**
Set Packet Read Timeout (UNIX only)
**/
JNIEXPORT jboolean JNICALL Java_jpcap_JpcapCaptor_setPacketReadTimeout
(JNIEnv *env, jobject obj, jint millis)
{
    jboolean success = JNI_FALSE;

#ifndef WIN32
    jint id = getJpcapID(env, obj);
    int fd = pcap_fileno(pcds[id]);
    int s;
    struct timeval tv;

    tv.tv_usec = (millis % 1000) * 1000;
    tv.tv_sec = millis / 1000;
    s = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    success = (s==0?JNI_TRUE:JNI_FALSE);
#endif

    return success;
}

/**
Get Packet Read Timeout (UNIX only)
**/
JNIEXPORT jint JNICALL Java_jpcap_JpcapCaptor_getPacketReadTimeout
(JNIEnv *env, jobject obj)
{
    jint rval = -1;

#ifndef WIN32
    jint id = getJpcapID(env, obj);
    int fd = pcap_fileno(pcds[id]);
    int s;
    struct timeval tv;
    socklen_t len = sizeof(struct timeval);

    s = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len);

    if (s == 0 && len == sizeof(struct timeval))
    {
        rval = (tv.tv_usec / 1000) + (tv.tv_sec * 1000);
    }
#endif

    return rval;
}

void dispatcher_handler(u_char *id,const struct pcap_pkthdr *header,
			const u_char *data)
{
  jobject packet;
  int ID=(int)id;

  JNIEnv *env=jni_envs[ID];

//  printf("enter:%d\n",ID);
  get_packet(*header,(u_char *)data,&packet,ID);
//  printf("got packet:%d\n",ID);
  (*env)->CallVoidMethod(env,jpcap_handlers[ID],handleMID,packet);
  DeleteLocalRef(packet);

//  printf("leave:%d\n",ID);
  YIELD();
}

void get_packet(struct pcap_pkthdr header,u_char *data,jobject *packet,int id){

  u_short nproto,tproto;
  short clen=header.caplen,hlen;
  u_char *orig_data=data;
  jbyteArray dataArray;

  JNIEnv *env=jni_envs[id];

  // Analyze network protocol
  // patch from Kenta
  switch(linktypes[id]){
  case DLT_RAW:
    // based on the hack for Raw IP
    nproto=ETHERTYPE_IP;
    clen-=datalink_hlen(id);
    break;
  case DLT_IEEE802:
  case DLT_EN10MB:
    nproto=get_network_type(data,id);
    clen-=datalink_hlen(id);
    break;
  default:
    // get_network_type() macro does NOT work for non-ether packets
    // and can cause crash
    nproto=UNKNOWN_PROTO;
    break;
  }

  //printf("detect:%d\n",nproto);
  if(clen>0){
    switch(nproto){
    case ETHERTYPE_IP:
      clen-=((struct ip *)skip_datalink_header(data,id))->ip_hl<<2;
      if(clen>0 &&
	 !(ntohs(((struct ip *)skip_datalink_header(data,id))->ip_off)&IP_OFFMASK))
	tproto=((struct ip *)skip_datalink_header(data,id))->ip_p;
      else
	tproto=ETHERTYPE_IP;
      break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      clen-=40;
      if(clen>0){
	u_char *dp=skip_datalink_header(data,id);
	struct ip6_ext *ip6_ext;

	tproto=((struct ip6_hdr *)dp)->ip6_nxt;
	while((tproto==IPPROTO_HOPOPTS || tproto==IPPROTO_DSTOPTS ||
	       tproto==IPPROTO_ROUTING || tproto==IPPROTO_AH ||
	       tproto==IPPROTO_FRAGMENT) && clen>0){
	  switch(tproto){
	  case IPPROTO_HOPOPTS: /* Hop-by-Hop option  */
	  case IPPROTO_DSTOPTS: /* Destination option */
	  case IPPROTO_ROUTING: /* Routing option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=(ip6_ext->ip6e_len+1)<<3;
	    clen-=(ip6_ext->ip6e_len+1)<<3;
	    break;
	  case IPPROTO_AH: /* AH option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=(ip6_ext->ip6e_len+2)<<2;
	    clen-=(ip6_ext->ip6e_len+2)<<2;
	    break;
	  case IPPROTO_FRAGMENT: /* Fragment option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=8;
	    clen-=8;
	    break;
	  }
	  if(tproto==IPPROTO_ESP || tproto==IPPROTO_NONE)
	    tproto=-1;
	}
      }
      break;
#endif
    case ETHERTYPE_ARP:
      /** XXX - assume that ARP is for Ethernet<->IPv4 **/
      clen-=28;
      if(clen>0) tproto=ETHERTYPE_ARP;
      break;
    case UNKNOWN_PROTO: //patch from Kenta
      tproto = UNKNOWN_PROTO;
      break;
    default:
      tproto=get_network_type(data,id);
    }
  }

  /** Check for truncated packet */
  if((tproto==IPPROTO_TCP && clen<TCPHDRLEN) ||
     (tproto==IPPROTO_UDP && clen<UDPHDRLEN) ||
     (tproto==IPPROTO_ICMP && clen<ICMPHDRLEN)){
    tproto=-1;
  }

  //printf("create:%d\n",tproto);
  /** Create packet object **/
  switch(tproto){
  case IPPROTO_TCP:
    *packet=AllocObject(TCPPacket);break;
  case IPPROTO_UDP:
    *packet=AllocObject(UDPPacket);break;
  case IPPROTO_ICMP:
    *packet=AllocObject(ICMPPacket);break;
  default:
    switch(nproto){
    case ETHERTYPE_IP:
      *packet=AllocObject(IPPacket);break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      *packet=AllocObject(IPPacket);break;
#endif
    case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
      *packet=AllocObject(ARPPacket);break;
    default:
      *packet=AllocObject(Packet);break;
    }
  }
  (*env)->CallVoidMethod(env,*packet,setPacketValueMID,
			     (jlong)header.ts.tv_sec,(jlong)header.ts.tv_usec,
			     (jint)header.caplen,(jint)header.len);

  //printf("datalink:%d\n",linktypes[id]);
  /** Analyze Datalink**/
  {
	jobject dlpacket=analyze_datalink(env,data,linktypes[id]);
    (*env)->CallVoidMethod(env,*packet,setDatalinkPacketMID,dlpacket);
	DeleteLocalRef(dlpacket);
  }

  //printf("network:%d\n",nproto);
  /** Analyze Network**/
  if(nproto != UNKNOWN_PROTO)
	data=skip_datalink_header(data,id);
  switch(nproto){
  case ETHERTYPE_IP:
    clen=ntohs(((struct ip *)data)->ip_len);
    hlen=analyze_ip(env,*packet,data);
    break;
#ifdef INET6
  case ETHERTYPE_IPV6:
    clen=ntohs(((struct ip6_hdr *)data)->ip6_plen);
	clen+=40; 
    hlen=analyze_ipv6(env,*packet,data);break;
#endif
  case ETHERTYPE_ARP:
    clen=hlen=analyze_arp(env,*packet,data);break;
  case UNKNOWN_PROTO:
    clen=header.caplen;
    hlen=0;
    break;
  default:
    clen=header.caplen-datalink_hlen(id);
	hlen=0;
    break;
  }
  if(nproto != UNKNOWN_PROTO &&
     tproto != UNKNOWN_PROTO &&
     clen>header.caplen-datalink_hlen(id)) 
    clen=header.caplen-datalink_hlen(id);
  data+=hlen;
  clen-=hlen;

  //printf("transport:%d\n",tproto);
  /** Analyze Transport **/
  switch(tproto){
  case IPPROTO_TCP:
    hlen=analyze_tcp(env,*packet,data); break;
  case IPPROTO_UDP:
	hlen=UDPHDRLEN;
    analyze_udp(env,*packet,data); break;
  case IPPROTO_ICMP:
    // updated by Damien Daspit 5/14/01
    //hlen=clen;
    hlen=ICMPHDRLEN;
	analyze_icmp(env,*packet,data,clen);break;
  default:
  {
    /*jbyteArray dataArray=(*jni_env)->NewByteArray(jni_env,clen);
    (*jni_env)->SetByteArrayRegion(jni_env,dataArray,0,clen,data);
    (*jni_env)->CallVoidMethod(jni_env,*packet,setPacketDataMID,dataArray);*/
    hlen=0;
    break;
  }
  }
  if(hlen>clen) //if the header is cut off
	  hlen=clen; //cut off hlen
  clen-=hlen;
  data+=hlen;
  hlen=(u_short)(data-orig_data);
  //printf("set data: clen=%d, hlen=%d,total=%d/%d\n",clen,hlen,header.len,header.caplen);

  dataArray=(*env)->NewByteArray(env,hlen);
  (*env)->SetByteArrayRegion(env,dataArray,0,hlen,orig_data);
  (*env)->CallVoidMethod(env,*packet,setPacketHeaderMID,dataArray);
  DeleteLocalRef(dataArray);

  if(clen>=0){
    dataArray=(*env)->NewByteArray(env,(jsize)clen);
    (*env)->SetByteArrayRegion(env,dataArray,0,(jsize)clen,data);
    (*env)->CallVoidMethod(env,*packet,setPacketDataMID,dataArray);
    DeleteLocalRef(dataArray);
  }
}

void set_Java_env(JNIEnv *env){
  if(Jpcap!=NULL) return;
  GlobalClassRef(Jpcap,"jpcap/JpcapCaptor");
  GlobalClassRef(JpcapHandler,"jpcap/PacketReceiver");
  GlobalClassRef(Packet,"jpcap/packet/Packet");
  GlobalClassRef(DatalinkPacket,"jpcap/packet/DatalinkPacket");
  GlobalClassRef(EthernetPacket,"jpcap/packet/EthernetPacket");
  GlobalClassRef(IPPacket,"jpcap/packet/IPPacket");
  GlobalClassRef(TCPPacket,"jpcap/packet/TCPPacket");
  GlobalClassRef(UDPPacket,"jpcap/packet/UDPPacket");
  GlobalClassRef(ICMPPacket,"jpcap/packet/ICMPPacket");
  GlobalClassRef(IPv6Option,"jpcap/packet/IPv6Option");
  GlobalClassRef(ARPPacket,"jpcap/packet/ARPPacket");
  GlobalClassRef(String,"java/lang/String");
  GlobalClassRef(Thread,"java/lang/Thread");
  GlobalClassRef(UnknownHostException,"java/net/UnknownHostException");
  GlobalClassRef(IOException,"java/io/IOException");

  if((*env)->ExceptionCheck(env)==JNI_TRUE){
	  (*env)->ExceptionDescribe(env);
	  return;
  }

  handleMID=(*env)->GetMethodID(env,JpcapHandler,"receivePacket",
				"(Ljpcap/packet/Packet;)V");
  setPacketValueMID=(*env)->GetMethodID(env,Packet,"setPacketValue",
					"(JJII)V");
  setDatalinkPacketMID=(*env)->GetMethodID(env,Packet,"setDatalinkPacket",
					   "(Ljpcap/packet/DatalinkPacket;)V");
  setPacketHeaderMID=(*env)->GetMethodID(env,Packet,"setPacketHeader","([B)V");
  setPacketDataMID=(*env)->GetMethodID(env,Packet,"setPacketData",
				       "([B)V");
  setEthernetValueMID=(*env)->GetMethodID(env,EthernetPacket,"setValue",
					  "([B[BS)V");
  // updated by Damien Daspit 5/7/01
  setIPValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv4Value",
		 "(BBZZZBZZZSSSSS[B[B)V");
  setIPv4OptionMID=(*env)->GetMethodID(env,IPPacket,"setOption","([B)V");
  // *******************************
  setIPv6ValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv6Value",
				      "(BBISBS[B[B)V");
  addIPv6OptHdrMID=(*env)->GetMethodID(env,IPPacket,"addOptionHeader",
				       "(Ljpcap/packet/IPv6Option;)V");
  // updated by Damien Daspit 5/7/01
  setTCPValueMID=(*env)->GetMethodID(env,TCPPacket,"setValue","(IIJJZZZZZZZZIS)V");
  // *******************************
  setTCPOptionMID=(*env)->GetMethodID(env,TCPPacket,"setOption","([B)V");
  setUDPValueMID=(*env)->GetMethodID(env,UDPPacket,"setValue","(III)V");
  setICMPValueMID=(*env)->GetMethodID(env,ICMPPacket,"setValue","(BBSSS)V");
  setICMPIDMID=(*env)->GetMethodID(env,ICMPPacket,"setID","(SS)V");
  setICMPTimestampMID=(*env)->GetMethodID(env,ICMPPacket,"setTimestampValue",
					  "(III)V");
  setICMPRedirectIPMID=(*env)->GetMethodID(env,ICMPPacket,"setRedirectIP",
				       "([B)V");
  getICMPRedirectIPMID=(*env)->GetMethodID(env,ICMPPacket,"getRedirectIP",
				       "()[B");
  setICMPRouterAdMID=(*env)->GetMethodID(env,ICMPPacket,"setRouterAdValue",
					 "(BBS[Ljava/lang/String;[I)V");
  setV6OptValueMID=(*env)->GetMethodID(env,IPv6Option,"setValue",
				       "(BBB)V");
  setV6OptOptionMID=(*env)->GetMethodID(env,IPv6Option,"setOptionData",
					"([B)V");
  setV6OptRoutingMID=(*env)->GetMethodID(env,IPv6Option,"setRoutingOption",
					  "(BB[[B)V");
  setV6OptFragmentMID=(*env)->GetMethodID(env,IPv6Option,"setFragmentOption",
					  "(SZI)V");
  setV6OptAHMID=(*env)->GetMethodID(env,IPv6Option,"setAHOption",
				    "(II)V");
  getSourceAddressMID=(*env)->GetMethodID(env,IPPacket,"getSourceAddress",
					  "()[B");
  getDestinationAddressMID=(*env)->GetMethodID(env,IPPacket,
					       "getDestinationAddress",
					       "()[B");
  setARPValueMID=(*env)->GetMethodID(env,ARPPacket,"setValue",
				     "(SSSSS[B[B[B[B)V");
  jpcapID=(*env)->GetFieldID(env,Jpcap,"ID","I");

  if((*env)->ExceptionCheck(env)==JNI_TRUE){
	  (*env)->ExceptionDescribe(env);
	  return;
  }
}
