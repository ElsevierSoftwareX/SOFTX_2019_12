#include <string.h>
#include <jni.h>
#include "it_unipr_netsec_tuntap_TuntapSocket.h"

#include <fcntl.h>  // O_RDWR
#include <string.h> // memset(), memcpy()
#include <stdio.h> // perror(), printf(), fprintf()
#include <stdlib.h> // exit(), malloc(), free()
#include <sys/ioctl.h> // ioctl()

// includes for struct ifreq, etc.
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>


#define __PNAME "TunSocketImp: "

/** Logs an error message. */
void printerr(const char* msg)
{  // append a header to the message
   char* hdr=__PNAME;
   int hdr_len=strlen(hdr);
   int msg_len=strlen(msg);
   char str[hdr_len+msg_len+1];
   strncpy(str,hdr,hdr_len);
   strncpy(str+hdr_len,msg,msg_len);
   str[hdr_len+msg_len]='\0';
   
   #ifdef _WIN32
      int err=WSAGetLastError();
      fprintf(stderr,"%s: %d",str,err);
   #else
      perror(str);
   #endif
}

JNIEXPORT jlong JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_open(JNIEnv* env, jobject obj, jboolean tun_j, jstring name_j)
{
	struct ifreq ifr;
	int fd, err;
    const char* devname;

	if ((fd=open("/dev/net/tun", O_RDWR))==-1)
	{	printerr("open /dev/net/tun");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	if (tun_j==0) ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
	else ifr.ifr_flags = IFF_TUN;
	
	if (name_j!=NULL)
	{	// ioctl use ifr_name as the name of TUN interface to open, e.g. "tun0"
		devname=(*env)->GetStringUTFChars(env,name_j,0); // devname BEGIN
		strncpy(ifr.ifr_name, devname, IFNAMSIZ);  
		(*env)->ReleaseStringUTFChars(env,name_j,devname); // devname END
	}
	if ((err=ioctl(fd, TUNSETIFF, (void *)&ifr))==-1)
	{	printerr("ioctl TUNSETIFF");
		close(fd);
		exit(1);
	}

	return fd;
}


JNIEXPORT void JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_close(JNIEnv* env, jobject obj, jlong fd)
{
	close(fd);
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_write(JNIEnv* env, jobject obj, jlong fd, jbyteArray data_j, jint off, jint len)
{
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);
   int nbytes=write(fd,(char*)(data+off),len);
   if (nbytes<0) 
   {	printerr("write()");
		exit(EXIT_FAILURE);
   }
   (*env)->ReleaseByteArrayElements(env,data_j,data,0);
   
   return nbytes;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_read(JNIEnv* env, jobject obj, jlong fd, jbyteArray data_j, jint off)
{
   jsize len=(*env)->GetArrayLength(env,data_j);
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);

   int nbytes=read(fd,(char*)(data+off),len);
   if (nbytes<0) 
   {  printerr("recv()");
      exit(EXIT_FAILURE);
   }
   (*env)->ReleaseByteArrayElements(env,data_j,data,0);
   
   return nbytes;
}
