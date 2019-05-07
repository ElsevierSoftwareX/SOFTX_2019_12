#!/bin/sh
JAVA_PATH=/usr/lib/jvm/jdk1.7.0_03
LIB_PATH=lib
#LIB_PATH=.
LIB_NAME=rawsck-32
SRC_FILES=src_c/it_unipr_netsec_rawsocket_SocketImp.c
echo :
echo : -------------------- MAKE LIB $LIB_NAME --------------------
echo :
#gcc -Wall -D_JNI_IMPLEMENTATION_ -I$JAVA_PATH/include -I$JAVA_PATH/include/linux -shared $SRC_FILES -o $LIB_PATH/librawsck.so
#gcc  -o $LIB_PATH/librawsck.so -shared -Wl,-soname,librawsck.so -I$JAVA_PATH/include -I$JAVA_PATH/include/linux $SRC_FILES -static -lc
gcc -o $LIB_PATH/lib$LIB_NAME.so -shared -I$JAVA_PATH/include -I$JAVA_PATH/include/linux $SRC_FILES
