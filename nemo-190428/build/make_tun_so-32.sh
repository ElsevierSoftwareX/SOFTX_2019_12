#!/bin/sh
JAVA_PATH=/usr/lib/jvm/jdk1.7.0_03
LIB_PATH=lib
#LIB_PATH=.
LIB_NAME=tuntap-64
SRC_FILES=src_c/it_unipr_netsec_tuntap_TunSocketImp.c
echo :
echo : -------------------- MAKE LIB $LIB_NAME --------------------
echo :
gcc -o $LIB_PATH/lib$LIB_NAME.so -shared -I$JAVA_PATH/include -I$JAVA_PATH/include/linux $SRC_FILES
