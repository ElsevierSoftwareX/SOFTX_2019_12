#!/bin/sh
JAVA_PATH=/opt/java/jdk1.7.0_03
#LIB_PATH=lib
LIB_PATH=.
LIB_NAME=qfilter
SRC_FILES=src_c/it_unipr_netsec_netfilter_NetfilterQueueImp.c
echo :
echo : -------------------- MAKE LIB $LIB_NAME --------------------
echo :
gcc -o $LIB_PATH/lib$LIB_NAME.so -shared -I$JAVA_PATH/include -I$JAVA_PATH/include/linux $SRC_FILES -lnfnetlink -lnetfilter_queue -mcmodel=large
