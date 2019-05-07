/* This implementation wraps the Unix Socket interface and provides methods that have only int or char* parameters.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


#ifdef _WIN32
   //#include <windows.h> // includes all windows header files
   #include <winsock2.h>
   #include <ws2tcpip.h>   
   #include <mstcpip.h> // for the patch for disabling socket error 10054 on recvfrom()
   #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12) // this too
#else
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
	 
   #include <sys/ioctl.h>
   #include <bits/ioctls.h>
   #include <net/if.h>
   #include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)	 
	 
#endif

#include <string.h> // DEBUG @@@@@@@@@@@@@@@@@@@@@@@@@@@@
#include <jni.h>
#include "it_unipr_netsec_rawsocket_Socket.h"

#define __PNAME "SocketImp: "


int DEBUG=0;


/** Fills an array with all zeros. */
/*void fillzero(unsigned char* buff, const int size)
{  int i;
   for (i=0; i<size; i++) buff[i]=0;
}*/


/** Converts a string into an ipv4 address, returning a struct in_addr. */
/*struct in_addr strtoipaddr(const char* str)
{  u_char addr[4];
   int k, i=0;
   fillzero(addr,4);
   for (k=0; k<4; k++)
   {  while (str[i]>='0' && str[i]<='9')
      {  addr[k]=addr[k]*10+(str[i]-'0');
         i++;
      }
      if (str[i]!='.') break;
      i++;
   }
   return *(struct in_addr*)addr;
}*/

/** Converts a 4-byte ipv4 address to integer. */
int _ip4ton(const char* addr)
{  return (addr[0]&0xff) | ((addr[1]&0xff)<<8) | ((addr[2]&0xff)<<16) | ((addr[3]&0xff)<<24);
}

/** Converts an integer to 4-byte ipv4 address. */
void _ntoip4(long n, char* addr)
{  addr[0]=n&0xff;
   addr[1]=(n>>8)&0xff;
   addr[2]=(n>>16)&0xff;
   addr[3]=(n>>24)&0xff;
}

/** Converts a integer to 2-byte array. */
void _ntobb(int n, char* buf)
{  buf[0]=(n>>8)&0xff;
   buf[1]=n&0xff;
}

/** Converts a 2-byte array to integer. */
int _bbton(const char* buf)
{  return (buf[0]&0xff) | ((buf[1]&0xff)<<8);
}


#ifdef _WIN32
int inet_pton(int af, const char *src, void *dst)
{  struct sockaddr_storage ss;
   int size = sizeof(ss);
   char src_copy[INET6_ADDRSTRLEN+1];
   ZeroMemory(&ss, sizeof(ss));
   strncpy (src_copy, src, INET6_ADDRSTRLEN+1);
   src_copy[INET6_ADDRSTRLEN] = 0;
   if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0)
   {  switch(af)
      {  case AF_INET: *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr; return 1;
         case AF_INET6: *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr; return 1;
      }
   }
   return 0;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{  struct sockaddr_storage ss;
   unsigned long s = size;
   ZeroMemory(&ss, sizeof(ss));
   ss.ss_family = af;
   switch(af)
   {  case AF_INET: ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src; break;
      case AF_INET6: ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src; break;
      default: return NULL;
   }
   return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0)? dst : NULL;
}
#endif



/** Prints a socket address structure. */
void debugSocktAddr(const char* str, const struct sockaddr *sockaddr, int sockaddr_len)
{  printf("DEBUG: %s%s",__PNAME,str);
   int i;
   for (i=0; i<sockaddr_len; i++)
   {  printf("%d ",((char*) sockaddr)[i]&0xff);
   }
   printf("\n");
}


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


JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_startup(JNIEnv* env, jclass class)
{
   #ifdef _WIN32
    // start Winsock2
   WSADATA wsinfo;
   if (WSAStartup(MAKEWORD(2,0), &wsinfo))
   {  printerr("starup(): Could not start WSA");
      exit(EXIT_FAILURE);
   }
   #endif
}


JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_cleanup(JNIEnv* env, jclass class)
{
   #ifdef _WIN32
   // clean Winsock2
   WSACleanup();
   #endif
}

JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_getPFINET6(JNIEnv* env, jclass class)
{  return (jint)PF_INET6;
}


JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_setdebug(JNIEnv* env, jclass class, jboolean enable)
{  DEBUG=enable;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_socket(JNIEnv* env, jobject obj, jint domain, jint type, jint protocol)
{
   if (DEBUG) printf("DEBUG: %ssocket(): domain=%d type=%d protocol=%d\n",__PNAME,(int)domain,(int)type,(int)ntohs(protocol));
   //if (DEBUG) printf("DEBUG: %ssocket(): domain=%d type=%d protocol=%d\n",__PNAME,(int)domain,(int)type,(int)protocol);
   jint sock=socket(domain,type,protocol);
   if(sock<0)
   {  printerr("socket(): Cannot open raw socket");
      //exit(EXIT_FAILURE);
   }
   #ifdef _WIN32
   else
   {  // disable error 10054 on recvfrom() caused by a Windows "bug" on processing ICMP destination unreachable
      BOOL bNewBehavior=FALSE;
      DWORD dwBytesReturned=0;
      WSAIoctl(sock,SIO_UDP_CONNRESET,&bNewBehavior,sizeof bNewBehavior,NULL,0,&dwBytesReturned,NULL,NULL);
   }
   #endif
   return sock;
}


JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_close(JNIEnv* env, jobject obj, jint sock)
{  close(sock);
}

/*JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_bindAllAddresses(JNIEnv* env, jobject obj, jint sock, jint sa_family)
{
   struct sockaddr* local_sockaddr;
   int sockaddr_len=0;
   if (sa_family==AF_INET)
   {  if (DEBUG) printf("DEBUG: %sbind(): IPv4\n",__PNAME);
      struct sockaddr_in ipv4_sockaddr;
      memset(&ipv4_sockaddr,0,sizeof(ipv4_sockaddr));
      ipv4_sockaddr.sin_family = AF_INET;
      ipv4_sockaddr.sin_addr.s_addr = INADDR_ANY;
      local_sockaddr=(struct sockaddr*) &ipv4_sockaddr;
      sockaddr_len=sizeof ipv4_sockaddr;
   }
   else
   if (sa_family==AF_INET6)
   {  if (DEBUG) printf("DEBUG: %sbind(): IPv6\n",__PNAME);
      struct sockaddr_in6 ipv6_sockaddr;
      memset(&ipv6_sockaddr,0,sizeof(ipv6_sockaddr));
      ipv6_sockaddr.sin6_family = AF_INET6;
      ipv6_sockaddr.sin6_flowinfo = 0;
      ipv6_sockaddr.sin6_addr = in6addr_any;
      local_sockaddr=(struct sockaddr*) &ipv6_sockaddr;
      sockaddr_len=sizeof ipv6_sockaddr;
   }
 
   int result=bind(sock,local_sockaddr,sockaddr_len);
   if (result<0)
   {  printerr("bind()");
      //exit(EXIT_FAILURE);
   }
   return result;
}*/


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_bind(JNIEnv* env, jobject obj, jint sock, jint sa_family, jbyteArray ipaddr_j, jint port)
{
   if (DEBUG) printf("DEBUG: %sbind()\n",__PNAME);
   jbyte* ipaddr=(*env)->GetByteArrayElements(env,ipaddr_j,0);
   
   struct sockaddr* local_sockaddr;
   int sockaddr_len=0;
   if (sa_family==AF_INET)
   {  //if (DEBUG) printf("DEBUG: %sbind(): AF_INET\n",__PNAME);
      struct sockaddr_in ipv4_sockaddr;
      memset(&ipv4_sockaddr,0,sizeof(ipv4_sockaddr));
      ipv4_sockaddr.sin_family = AF_INET;
	  ipv4_sockaddr.sin_port = htons(port);
      //ipv4_sockaddr.sin_addr.s_addr = INADDR_ANY;
      // copy 'ipaddr' to 'ipv4_sockaddr.sin_addr.s_addr'
	  ipv4_sockaddr.sin_addr.s_addr=_ip4ton(ipaddr);
      local_sockaddr=(struct sockaddr*) &ipv4_sockaddr;
      sockaddr_len=sizeof ipv4_sockaddr;
   }
   else
   if (sa_family==AF_INET6)
   {  //if (DEBUG) printf("DEBUG: %sbind(): AF_INET6\n",__PNAME);
      struct sockaddr_in6 ipv6_sockaddr;
      memset(&ipv6_sockaddr,0,sizeof(ipv6_sockaddr));
      ipv6_sockaddr.sin6_family = AF_INET6;
      ipv6_sockaddr.sin6_port = port;
      ipv6_sockaddr.sin6_flowinfo = 0;
      //ipv6_sockaddr.sin6_addr = in6addr_any;
      // copy 'ipaddr' to 'ipv6_sockaddr.sin6_addr.s6_addr'
      memcpy(ipv6_sockaddr.sin6_addr.s6_addr, ipaddr, sizeof ipaddr);
      local_sockaddr=(struct sockaddr*) &ipv6_sockaddr;
      sockaddr_len=sizeof ipv6_sockaddr;
   }
 
   if (DEBUG) debugSocktAddr("bind(): ",local_sockaddr,sockaddr_len);

   int result=bind(sock,local_sockaddr,sockaddr_len);
   (*env)->ReleaseByteArrayElements(env,ipaddr_j,ipaddr,0);
   if (result<0)
   {  printerr("bind()");
      //exit(EXIT_FAILURE);
   }   
   return result;
}


/*JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_bind(JNIEnv* env, jobject obj, jint sock, jbyteArray addr_j, jint addrlen)
{
   jbyte* addr=(*env)->GetByteArrayElements(env,addr_j,0);
   struct sockaddr* local_sockaddr=(struct sockaddr*)addr;
   int result=bind(sock,local_sockaddr,addrlen);
   if (result<0)
   {  printerr("bind()");
      exit(EXIT_FAILURE);
   }
   (*env)->ReleaseByteArrayElements(env,addr_j,addr,0);
   return result;
}*/


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_sendto(JNIEnv* env, jobject obj, jint sock, jbyteArray data_j, jint off, jint len, jint flags, jint sa_family, jstring daddr_j, jint port)
{
   struct sockaddr* dest_sockaddr;
   int sockaddr_len=0;
   if (DEBUG) printf("DEBUG: %ssendto()\n",__PNAME);
      
   if (sa_family==AF_INET)
   {  //if (DEBUG) printf("DEBUG: %ssendto(): AF_INET\n",__PNAME);
      struct sockaddr_in ipv4_sockaddr;
      memset(&ipv4_sockaddr,0,sizeof(ipv4_sockaddr));
      ipv4_sockaddr.sin_family=AF_INET;
      //ipv4_sockaddr.sin_addr=ipv4_addr;
      const char* daddr=(*env)->GetStringUTFChars(env,daddr_j,0); // daddr BEGIN
      inet_pton(AF_INET,daddr,&ipv4_sockaddr.sin_addr);
      (*env)->ReleaseStringUTFChars(env,daddr_j,daddr); // daddr END
      ipv4_sockaddr.sin_port=htons(port);
      dest_sockaddr=(struct sockaddr*) &ipv4_sockaddr;
      sockaddr_len=sizeof ipv4_sockaddr;
   }
   else
   if (sa_family==AF_INET6)
   {  //if (DEBUG) printf("DEBUG: %ssendto():AF_INET6\n",__PNAME);
      struct sockaddr_in6 ipv6_sockaddr;
      memset(&ipv6_sockaddr,0,sizeof(ipv6_sockaddr));
      ipv6_sockaddr.sin6_family=AF_INET6;
      ipv6_sockaddr.sin6_flowinfo=0;
      //ipv6_sockaddr.sin6_addr=ipv6_addr;
      const char* daddr=(*env)->GetStringUTFChars(env,daddr_j,0); // daddr BEGIN
      inet_pton(AF_INET6,daddr,&ipv6_sockaddr.sin6_addr);
      (*env)->ReleaseStringUTFChars(env,daddr_j,daddr); // daddr END 
      ipv6_sockaddr.sin6_port=htons(port);
      dest_sockaddr=(struct sockaddr*) &ipv6_sockaddr;
      sockaddr_len=sizeof ipv6_sockaddr;
   }
   #ifndef _WIN32
   else
   if (sa_family==AF_PACKET)
   {  //if (DEBUG) printf("DEBUG: %ssendto(): AF_PACKET\n",__PNAME);
      struct ifreq ifr;
      struct sockaddr_ll device;
      memset(&device, 0, sizeof(device));

	  const char* interface=(*env)->GetStringUTFChars(env,daddr_j,0); // interface BEGIN
      if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
      {  printerr("sendto(): if_nametoindex() failed to obtain interface index ");
         exit(EXIT_FAILURE);
      }
      if (DEBUG) printf("DEBUG: %ssendto(): index for interface %s: %i\n", __PNAME, interface, device.sll_ifindex);
  
      // Use ioctl() to look up interface name and get its MAC address.
      memset(&ifr, 0, sizeof(ifr));
      snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
      if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
      {  printerr("sendto(): ioctl() failed to get source MAC address ");
         exit(EXIT_FAILURE);
      }
      (*env)->ReleaseStringUTFChars(env,daddr_j,interface); // interface END

      // Copy source MAC address.
      uint8_t src_mac[6];
      memcpy(src_mac,ifr.ifr_hwaddr.sa_data,6*sizeof(uint8_t));
  
      // Fill out sockaddr_ll.
      device.sll_family = AF_PACKET;
      memcpy(device.sll_addr,src_mac,6*sizeof(uint8_t));
      device.sll_halen = 6;

      dest_sockaddr=(struct sockaddr*) &device;
      sockaddr_len=sizeof(device);
   }
   #endif

   if (DEBUG) debugSocktAddr("sendto(): ",dest_sockaddr,sockaddr_len);

   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0); // data BEGIN
   int nbytes=sendto(sock,(char*)(data+off),len,flags,dest_sockaddr,sockaddr_len);
   (*env)->ReleaseByteArrayElements(env,data_j,data,0); // data BEGIN
   if(nbytes<0) 
   {  printerr("sendto()");
      //exit(EXIT_FAILURE);
   }   
   return nbytes;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_recv(JNIEnv* env, jobject obj, jint sock, jbyteArray data_j, jint off, jint flags)
{
   if (DEBUG) printf("DEBUG: %srecv()\n", __PNAME);
   jsize len=(*env)->GetArrayLength(env,data_j);
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);
   int nbytes=recv(sock,(char*)(data+off),len,flags);
   (*env)->ReleaseByteArrayElements(env,data_j,data,0);
   if(nbytes<0) 
   {  printerr("recv()");
      //exit(EXIT_FAILURE);
   }
   else if (DEBUG) printf("DEBUG: %srecv(): received\n", __PNAME);
   return nbytes;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_recvfrom(JNIEnv* env, jobject obj, jint sock, jbyteArray data_j, jint off, jint flags, jbyteArray addr_j, jbyteArray port_j)
{
   if (DEBUG) printf("DEBUG: %srecvfrom()\n", __PNAME);
   jsize data_len=(*env)->GetArrayLength(env,data_j);
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);
 
   struct sockaddr_storage src_sockaddr;
   socklen_t sockaddr_len=sizeof(src_sockaddr);
   //bzero(&src_sockaddr,sockaddr_len);  
  
   int nbytes=recvfrom(sock,(char*)(data+off),data_len,flags,(struct sockaddr*)&src_sockaddr,&sockaddr_len);
   (*env)->ReleaseByteArrayElements(env,data_j,data,0); 
   if (nbytes<0) 
   {  printerr("recvfrom()");
      //exit(EXIT_FAILURE);
      return nbytes;
   }
   
   //if (DEBUG) debugSocktAddr("recvfrom(): ",(struct sockaddr*)&src_sockaddr,sockaddr_len);

   //jsize addr_len=(*env)->GetArrayLength(env,addr_j);
   //if (DEBUG) printf("DEBUG: %srecvfrom(): addr_j len: %d\n",__PNAME,addr_len);
   jbyte* addr=(*env)->GetByteArrayElements(env,addr_j,0);
   jbyte* port=(*env)->GetByteArrayElements(env,port_j,0);
   int sa_family=((struct sockaddr*)&src_sockaddr)->sa_family;
   if (DEBUG) printf("DEBUG: %srecvfrom(): received, address family: %d\n",__PNAME,sa_family);
   if (sa_family==AF_INET)
   {  struct sockaddr_in* ipv4_sockaddr=(struct sockaddr_in*)&src_sockaddr;
      //if (DEBUG) printf("DEBUG: %srecvfrom(): src addr=%s, port=%d\n",__PNAME,inet_ntoa(ipv4_sockaddr->sin_addr),htons(ipv4_sockaddr->sin_port));
      _ntobb(htons(ipv4_sockaddr->sin_port),port);
      _ntoip4(ipv4_sockaddr->sin_addr.s_addr,addr);
   }
   else
   if (sa_family==AF_INET6)
   {  struct sockaddr_in6* ipv6_sockaddr=(struct sockaddr_in6*)&src_sockaddr;
      _ntobb(htons(ipv6_sockaddr->sin6_port),port);
      memcpy(addr,ipv6_sockaddr->sin6_addr.s6_addr,16*sizeof(uint8_t));
   }
   #ifndef _WIN32
   else
   if (sa_family==AF_PACKET)
   {  struct sockaddr_ll* device=(struct sockaddr_ll*)&src_sockaddr;
      //if (DEBUG) printf("DEBUG: %srecvfrom(): src addr=%02x:%02x:%02x:%02x:%02x:%02x\n",__PNAME,device->sll_addr[0],device->sll_addr[1],device->sll_addr[2],device->sll_addr[3],device->sll_addr[4],device->sll_addr[5]);
      memcpy(addr,device->sll_addr,6*sizeof(uint8_t));
   }
   #endif
   (*env)->ReleaseByteArrayElements(env,addr_j,addr,0);
   (*env)->ReleaseByteArrayElements(env,port_j,port,0);
   return nbytes;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_setsockopt(JNIEnv* env, jobject obj, jint sock, jint level, jint opt, jbyteArray value_j, jint off, jint len)
{
   if (value_j==NULL || len==0)
   {  if (setsockopt(sock,level,opt,NULL,0)<0)
      {  printerr("setsockopt()");
         //exit(EXIT_FAILURE);
      }
      return -1;
   }
   // else
   jbyte* value=(*env)->GetByteArrayElements(env,value_j,0);
   int result=setsockopt(sock,level,opt,(void*)(value+off),len);
   (*env)->ReleaseByteArrayElements(env,value_j,value,0);
   if (result<0)
   {  printerr("setsockopt()");
      //exit(EXIT_FAILURE);
   }
   return result;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_getsockopt(JNIEnv* env, jobject obj, jint sock, jint level, jint opt, jbyteArray value_j, jint off)
{
   jsize len=(*env)->GetArrayLength(env,value_j);
   jbyte* value=(*env)->GetByteArrayElements(env,value_j,0);
   int nbytes=len;
   int result=getsockopt(sock,level,opt,(char*)(value+off),&nbytes);
   (*env)->ReleaseByteArrayElements(env,value_j,value,0);
   if (result<0)
   {  printerr("getsockopt()");
      //exit(EXIT_FAILURE);
   }
   return nbytes;
}
