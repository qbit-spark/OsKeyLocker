#include <windows.h>
#include <dpapi.h>
#include <jni.h>
#include "com_OsKeyLocker_platform_windows_WindowsDPAPI.h"

JNIEXPORT jbyteArray JNICALL Java_com_OsKeyLocker_platform_windows_WindowsDPAPI_protect
  (JNIEnv *env, jobject obj, jbyteArray data) {

    jbyte* dataBytes = env->GetByteArrayElements(data, NULL);
    jsize dataLength = env->GetArrayLength(data);

    DATA_BLOB dataIn;
    dataIn.pbData = (BYTE*)dataBytes;
    dataIn.cbData = dataLength;

    DATA_BLOB dataOut;

    if (CryptProtectData(&dataIn, L"OsKeyLocker", NULL, NULL, NULL, 0, &dataOut)) {
        jbyteArray result = env->NewByteArray(dataOut.cbData);
        env->SetByteArrayRegion(result, 0, dataOut.cbData, (jbyte*)dataOut.pbData);
        LocalFree(dataOut.pbData);
        env->ReleaseByteArrayElements(data, dataBytes, JNI_ABORT);
        return result;
    } else {
        env->ReleaseByteArrayElements(data, dataBytes, JNI_ABORT);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_OsKeyLocker_platform_windows_WindowsDPAPI_unprotect
  (JNIEnv *env, jobject obj, jbyteArray data) {

    jbyte* dataBytes = env->GetByteArrayElements(data, NULL);
    jsize dataLength = env->GetArrayLength(data);

    DATA_BLOB dataIn;
    dataIn.pbData = (BYTE*)dataBytes;
    dataIn.cbData = dataLength;

    DATA_BLOB dataOut;
    LPWSTR description;

    if (CryptUnprotectData(&dataIn, &description, NULL, NULL, NULL, 0, &dataOut)) {
        jbyteArray result = env->NewByteArray(dataOut.cbData);
        env->SetByteArrayRegion(result, 0, dataOut.cbData, (jbyte*)dataOut.pbData);
        LocalFree(dataOut.pbData);
        LocalFree(description);
        env->ReleaseByteArrayElements(data, dataBytes, JNI_ABORT);
        return result;
    } else {
        env->ReleaseByteArrayElements(data, dataBytes, JNI_ABORT);
        return NULL;
    }
}