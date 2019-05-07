@echo off
set JAVA_PATH=c:\programmi\java\jdk1.8.0_162
set LIB_PATH=lib
set LIB_NAME=rawsck-64
set SRC_FILES=src_c/it_unipr_netsec_rawsocket_SocketImp.c
echo :
echo : -------------------- MAKE LIB %LIB_NAME% --------------------
echo :
rem gcc -Wall -D_JNI_IMPLEMENTATION_ -Wl,--kill-at -I%JAVA_PATH%\include -I%JAVA_PATH%\include\win32 -shared %SRC_FILES% -o %LIB_PATH%\rawsck.dll -l wsock32
@echo on
gcc -Wall -D_JNI_IMPLEMENTATION_ -Wl,--kill-at -o %LIB_PATH%/%LIB_NAME%.dll -shared -I%JAVA_PATH%/include -I%JAVA_PATH%/include/win32 %SRC_FILES% -l wsock32 -l Ws2_32 -m64