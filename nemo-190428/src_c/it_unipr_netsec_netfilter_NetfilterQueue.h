/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class it_unipr_netsec_netfilter_NetfilterQueue */

#ifndef _Included_it_unipr_netsec_netfilter_NetfilterQueue
#define _Included_it_unipr_netsec_netfilter_NetfilterQueue
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     it_unipr_netsec_netfilter_NetfilterQueue
 * Method:    open
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_it_unipr_netsec_netfilter_NetfilterQueue_open
  (JNIEnv *, jobject);

/*
 * Class:     it_unipr_netsec_netfilter_NetfilterQueue
 * Method:    close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_netfilter_NetfilterQueue_close
  (JNIEnv *, jobject, jlong);

/*
 * Class:     it_unipr_netsec_netfilter_NetfilterQueue
 * Method:    run
 * Signature: (JILit/unipr/netsec/netfilter/PacketHandler;)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_netfilter_NetfilterQueue_run
  (JNIEnv *, jobject, jlong, jint, jobject);

#ifdef __cplusplus
}
#endif
#endif