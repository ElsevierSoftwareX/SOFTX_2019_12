/*
    Copyright 2008 Wolfgang Ginolas

    This file is part of P2PVPN.

    P2PVPN is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <objbase.h>
#include <winioctl.h>

#include <jni.h>
#include "it_unipr_netsec_tuntap_TuntapSocket.h"


#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_COMPONENT_ID_PREFIX "tap"

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define TAPSUFFIX         ".tap"

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)

typedef struct {
    HANDLE fd;
    HANDLE read_event;
    HANDLE write_event;
    OVERLAPPED read_overlapped;
    OVERLAPPED write_overlapped;    
} TapData;


/** Return: error? */
int findTapDevice(char *deviceID, int deviceIDLen, char *deviceName, int deviceNameLen, int skip) {
    HKEY adapterKey;
    int i;
    LONG status;
    DWORD len;
    char keyI[1024];
    char keyName[1024];
    HKEY key;
    
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey);

    if (status != ERROR_SUCCESS) {
        printf("Could not open key '%s'!\n", ADAPTER_KEY);
        return 1;
    }

    strncpy(deviceID, "", deviceIDLen);
    
    for (i=0; deviceID[0]=='\0' && ERROR_SUCCESS==RegEnumKey(adapterKey, i, keyI, sizeof(keyI)); i++) {
        char componentId[256];
        
        snprintf(keyName, sizeof(keyName), "%s\\%s", ADAPTER_KEY, keyI);
        status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);
        if (status != ERROR_SUCCESS) {
            printf("Could not open key '%s'!\n", keyName);
            return 1;
        }
        
        len = sizeof(componentId);
        status=RegQueryValueEx(key, "ComponentId", NULL, NULL, (unsigned char*)componentId, &len);
        if (status == ERROR_SUCCESS && 
                strncmp(componentId, TAP_COMPONENT_ID_PREFIX, strlen(TAP_COMPONENT_ID_PREFIX))==0) {
            if (skip<1) {
                len = deviceIDLen;
                RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, (unsigned char*)deviceID, &len);
            } else {
                skip--;
            }
        }

        RegCloseKey(key);
    }    
    
    RegCloseKey(adapterKey);

    if (deviceID[0]==0) return 1;
    
    snprintf(keyName, sizeof(keyName), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, deviceID);
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);
    if (status!=ERROR_SUCCESS) return 1;

    len = deviceNameLen;
    status=RegQueryValueEx(key, "Name", NULL, NULL, (unsigned char*)deviceName, &len);
    RegCloseKey(key);
    if (status!=ERROR_SUCCESS) return 1;
    
    return 0;
}


void setTapDataDev(JNIEnv *env, jobject this, TapData *tapData, char* dev) {
    jfieldID jfd, jdev; 
    jclass jclass; 
    jstring jstr;
    
    jclass = (*env)->GetObjectClass(env, this); 
    
    jfd = (*env)->GetFieldID(env, jclass, "cPtr", "J"); 
    (*env)->SetLongField(env, this, jfd , (jlong)tapData);
    
    jstr = (*env)->NewStringUTF(env, dev);
    jdev = (*env)->GetFieldID(env, jclass, "dev", "Ljava/lang/String;"); 
    (*env)->SetObjectField(env, this, jdev , jstr);
}


TapData *getTapData(JNIEnv *env, jobject this) {
    jfieldID jfd; 
    jclass jclass; 

    jclass = (*env)->GetObjectClass(env, this); 
    
    jfd = (*env)->GetFieldID(env, jclass, "cPtr", "J"); 
    return (TapData*)((*env)->GetLongField(env, this, jfd));
}


/* Return: pointer to TAP data, or -1 (not TAP found), or -2 (could not open TAP) */
JNIEXPORT jlong JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_open(JNIEnv* env, jobject obj, jboolean tun_j, jstring name_j) {
    char deviceId[256];
    char deviceName[256];
    char tapPath[256];
    TapData *tapData;
    unsigned long len = 0;
    int status;
    int skip = 0;
    
    tapData = malloc(sizeof(TapData));

    do {
        if (findTapDevice(deviceId, sizeof(deviceId), deviceName, sizeof(deviceName), skip)) {
            printf("Could not find TAP interface %s\n", tapPath);
            return skip==0 ? -1 : -2; // TODO
        }
        printf("TAP[device-ID]: '%s'\n", deviceId);
        printf("TAP[device-name]: '%s'\n", deviceName);

        snprintf(tapPath, sizeof(tapPath), "%s%s%s", USERMODEDEVICEDIR, deviceId, TAPSUFFIX);

        tapData->fd = CreateFile(tapPath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM |FILE_FLAG_OVERLAPPED, 0);   

        if (tapData->fd == INVALID_HANDLE_VALUE) {
            printf("Could not open '%s'!\n", tapPath);
            skip++;
        }
    }
	while (tapData->fd == INVALID_HANDLE_VALUE);
    
    status = TRUE;
    DeviceIoControl(tapData->fd, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof (status), &status, sizeof (status), &len, NULL);

    tapData->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    tapData->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    tapData->read_overlapped.Offset = 0;
    tapData->read_overlapped.OffsetHigh = 0;
    tapData->read_overlapped.hEvent = tapData->read_event;

    tapData->write_overlapped.Offset = 0;
    tapData->write_overlapped.OffsetHigh = 0;
    tapData->write_overlapped.hEvent = tapData->write_event;

    //setTapDataDev(env, obj, tapData, deviceName);
    return (jlong)tapData;
}

JNIEXPORT void JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_close(JNIEnv* env, jobject obj, jlong fd) {
    TapData *tapData;

    tapData = (TapData*)fd;
    CloseHandle(tapData->fd);
    free(tapData);
}

JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_write(JNIEnv* env, jobject obj, jlong fd, jbyteArray data_j, jint off, jint len) {
    TapData *tapData;
    jbyte *b;
    DWORD written;
    BOOL result;
    
    //tapData = getTapData(env, obj);
	tapData = (TapData*)fd;
    b = (*env)->GetByteArrayElements(env, data_j, NULL);
    
    result = GetOverlappedResult(tapData->fd, &tapData->write_overlapped, &written, FALSE);

    if (!result && GetLastError() == ERROR_IO_INCOMPLETE) {
		WaitForSingleObject(tapData->write_event, INFINITE);
	}

    WriteFile(tapData->fd, b+off, len, &written, &tapData->write_overlapped);
    
    (*env)->ReleaseByteArrayElements(env, data_j, b, JNI_ABORT);
	
	return len;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TuntapSocket_read(JNIEnv* env, jobject obj, jlong fd, jbyteArray data_j, jint off) {
    TapData *tapData;
    jbyte *b;
    DWORD len;
    BOOL result;
    
    //tapData = getTapData(env, obj);
	tapData = (TapData*)fd;
    b = (*env)->GetByteArrayElements(env, data_j, NULL);
    
    result = ReadFile(tapData->fd, b+off, (*env)->GetArrayLength(env, data_j), &len, &tapData->read_overlapped);
    
    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            WaitForSingleObject(tapData->read_event, INFINITE);
            GetOverlappedResult(tapData->fd, &tapData->read_overlapped, &len, FALSE);
        }
    }
   
    (*env)->ReleaseByteArrayElements(env, data_j, b, 0);

    return len;
}
