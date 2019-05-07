#include <jni.h>
#include "it_unipr_netsec_tuntap_TuntapSocket.h"
//#include <fcntl.h>  // O_RDWR
#include <string.h> // memset(), memcpy()
#include <stdio.h> // perror(), printf(), fprintf()
#include <stdlib.h> // exit(), malloc(), free()
#include <sys/ioctl.h> // ioctl()

// includes for struct ifreq, etc.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h> // struct socketaddr_ctl
//#include <linux/if.h>

// includes for Mac
#include <net/if_utun.h> // UTUN_CONTROL_NAME
#include <errno.h>
#include <syslog.h>
#include <unistd.h>


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
   perror(str);
}

JNIEXPORT jlong JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_open(JNIEnv* env, jobject obj, jboolean tun_j, jstring name_j)
{
	struct sockaddr_ctl sc;
	struct ctl_info ctlInfo;
	int fd;

	memset(&ctlInfo, 0, sizeof(ctlInfo));
	if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >= sizeof(ctlInfo.ctl_name)) {
		fprintf(stderr,"UTUN_CONTROL_NAME too long");
		return -1;
	}
	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) {
		perror("socket(SYSPROTO_CONTROL)");
		return -1;
	}
	if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
		perror("ioctl(CTLIOCGINFO)");
		close(fd);
		return -1;
	}
	printf("ctl_info: {ctl_id: %ud, ctl_name: %s}", ctlInfo.ctl_id, ctlInfo.ctl_name);
	sc.sc_id = ctlInfo.ctl_id;
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_unit = 2;	/* Only have one, in this example... */
	
	// If the connect is successful, a tun%d device will be created, where "%d" is our unit number -1
	if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
		perror("connect(AF_SYS_CONTROL)");
		close(fd);
		return -1;
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
