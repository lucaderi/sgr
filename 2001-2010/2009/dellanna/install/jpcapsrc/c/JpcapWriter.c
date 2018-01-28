#include<pcap.h>
#include<jni.h>

#ifndef WIN32
#include<netinet/in.h>
#endif
#include<netinet/in_systm.h>
#include<netinet/ip.h>

#pragma export on
#include"jpcap_JpcapWriter.h"
#pragma export reset

#include"Jpcap_sub.h"

pcap_t *pcdd=NULL;
pcap_dumper_t *pdt=NULL;

JNIEXPORT jstring JNICALL
Java_jpcap_JpcapWriter_nativeOpenDumpFile(JNIEnv *env,jobject obj,jstring filename,
										  jint id){
  char *file;

  if(pcds[id]==NULL){
	  return NewString("The jpcap is not instantiated.");
  }

  file=(char *)(*env)->GetStringUTFChars(env,filename,0);
  
  pcdd=pcds[id];
  pdt=pcap_dump_open(pcds[id],file);

  (*env)->ReleaseStringUTFChars(env,filename,file);

  if(pdt==NULL){
	  return NewString(pcap_geterr(pcds[id]));
  }

  //set_Java_env(env);
  return NULL;
}

JNIEXPORT void JNICALL
Java_jpcap_JpcapWriter_close(JNIEnv *env,jobject obj){
	if(pdt!=NULL){
		pcap_dump_close(pdt);
		free(pcdd);
		pcdd=NULL;
	}
	pdt=NULL;
}

JNIEXPORT void JNICALL
Java_jpcap_JpcapWriter_writePacket(JNIEnv *env,jobject obj,jobject packet){
	jbyteArray header,body;
	int hlen,blen;
	struct pcap_pkthdr hdr;
	char buf[MAX_PACKET_SIZE];

	hdr.ts.tv_sec=(long)GetLongField(Packet,packet,"sec");
	hdr.ts.tv_usec=(long)GetLongField(Packet,packet,"usec");
	hdr.caplen=GetIntField(Packet,packet,"caplen");
	hdr.len=GetIntField(Packet,packet,"len");

	header=GetObjectField(Packet,packet,"[B","header");
	body=GetObjectField(Packet,packet,"[B","data");

	hlen=(*env)->GetArrayLength(env,header);
	blen=(*env)->GetArrayLength(env,body);

	(*env)->GetByteArrayRegion(env,header,0,hlen,buf);
	(*env)->GetByteArrayRegion(env,body,0,blen,(char *)(buf+hlen));

	pcap_dump((u_char *)pdt,&hdr,buf);
}
