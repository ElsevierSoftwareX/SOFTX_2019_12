/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class it_unipr_netsec_tuntap_TuntapSocket */

#ifndef _Included_it_unipr_netsec_tuntap_TuntapSocket
#define _Included_it_unipr_netsec_tuntap_TuntapSocket
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     it_unipr_netsec_tuntap_TuntapSocket
 * Method:    open
 * Signature: (ZLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_open
  (JNIEnv *, jobject, jboolean, jstring);

/*
 * Class:     it_unipr_netsec_tuntap_TuntapSocket
 * Method:    close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_close
  (JNIEnv *, jobject, jlong);

/*
 * Class:     it_unipr_netsec_tuntap_TuntapSocket
 * Method:    write
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_write
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint);

/*
 * Class:     it_unipr_netsec_tuntap_TuntapSocket
 * Method:    read
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_read
  (JNIEnv *, jobject, jlong, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif
