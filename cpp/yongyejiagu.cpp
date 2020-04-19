//
// Created by yongye
//

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <cstdlib>
#include <string>
#include <ostream>
#include <map>


#define TAG "yongye"
#define log_info(fmt,args...) __android_log_print(ANDROID_LOG_INFO, TAG, (const char *) fmt, ##args)
#define log_err(fmt,args...) __android_log_print(ANDROID_LOG_ERROR, TAG, (const char *) fmt, ##args)

#ifdef LOG_DBG
#define log_dbg //log_info
#else
#define log_dbg(...)
#endif

char* jstringToChar(JNIEnv* env, jstring jstr) {
    char* rtn = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("GB2312");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char*) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return rtn;
}

jbyteArray readDexFileFromApk(JNIEnv* env, jobject oApplication){
    //调用java层方法从原DEX中获取壳DEX数据
    log_dbg("开始获取壳DEX数据");
    jclass jcFUtil = env->FindClass("cn/yongye/nativeshell/common/FileUtils");
    jbyteArray jbaDex = static_cast<jbyteArray>(env->CallStaticObjectMethod(jcFUtil,
                                                                            env->GetStaticMethodID(
                                                                                    jcFUtil,
                                                                                    "readDexFileFromApk",
                                                                                    "(Landroid/content/Context;)[B"),
                                                                            oApplication));
    __android_log_write(ANDROID_LOG_WARN, "yongye", "成功获取到壳DEX数据");
    return jbaDex;
}

/**
 *  解密原始DEX
 * @param env
 * @param jbaShellDex
 * @return
 */
jobjectArray decyptSrcDex(JNIEnv *env, jobject oApplication, jbyteArray jbaShellDex){
    __android_log_write(ANDROID_LOG_WARN, "yongye", "开始解密原始DEX");
    jbyte* jbDEX = env->GetByteArrayElements(jbaShellDex, JNI_FALSE);
    jsize inShDexLen = env->GetArrayLength(jbaShellDex);

    char * ptShDex = NULL;
    if(inShDexLen > 0){
        ptShDex = (char*)malloc(inShDexLen + 1);
        memcpy(ptShDex, jbDEX, inShDexLen);
        ptShDex[inShDexLen] = 0;
    }
    env->ReleaseByteArrayElements(jbaShellDex, jbDEX, 0);

    char *ptEncryptedSrcDexLen = &ptShDex[inShDexLen - 4];
    char ptSrcDEXLen[5] = {0};
    int inStart = 0;
    for (int i = 3; i >= 0; i--)
    {
        if (memcmp(&ptShDex[i], "\xff", 1) == 0)
            continue;
        ptSrcDEXLen[inStart] = ptEncryptedSrcDexLen[i] ^ 0xff;
        inStart += 1;
    }
    int inSrcDexLen = *(int*)ptSrcDEXLen;
    char *ptSrcDex = (char *)(malloc(inSrcDexLen + 1));
    memcpy(ptSrcDex, &ptShDex[inShDexLen-inSrcDexLen-4], inSrcDexLen);
    for(int i=0; i<inSrcDexLen; i++){
        ptSrcDex[i] ^= 0xff;
    }
    log_err("yongye");
    __android_log_write(ANDROID_LOG_ERROR, "yongye", "解密完成");
    // __android_log_print(ANDROID_LOG_ERROR, "yongye", "DEX长度为：%d", inSrcDexLen);
    log_err("DEX长度为：%d", inSrcDexLen);
    __android_log_write(ANDROID_LOG_ERROR, "yongye", ptSrcDex);
    jclass clsByteBuffer = env->FindClass("java/nio/ByteBuffer");

    jbyteArray baSrcDex = env->NewByteArray(inSrcDexLen);
    env->SetByteArrayRegion(baSrcDex, 0, inSrcDexLen, (jbyte*)ptSrcDex);
    jobject oDexByteBufferNull = env->CallStaticObjectMethod(clsByteBuffer, env->GetStaticMethodID(clsByteBuffer, "allocate", "(I)Ljava/nio/ByteBuffer;"),
                                                         inSrcDexLen);
    jobject oDexByteBuffer = env->CallStaticObjectMethod(clsByteBuffer, env->GetStaticMethodID(clsByteBuffer, "wrap", "([B)Ljava/nio/ByteBuffer;"), baSrcDex);
    jobjectArray baDexBufferArray = env->NewObjectArray(1, clsByteBuffer, oDexByteBuffer);
    return baDexBufferArray;
}

/**
 *  加载原始DEX
 * @param env
 * @param oApplication
 * @param stSrcDEXFp
 */
void loadSrcDEX(JNIEnv *env, jobject oApplication, jobjectArray ptSrcDex){
    __android_log_write(ANDROID_LOG_WARN, "yongye", "开始加载原始DEX");

    jclass clsContextWrapper = env->FindClass("android/content/ContextWrapper");
    jclass clsFile = env->FindClass("java/io/File");
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");
    jclass clsFileUtils = env->FindClass("cn/yongye/nativeshell/common/FileUtils");
    jclass clsMap = env->FindClass("java/util/Map");
//    jclass clsDexLoader = env->FindClass("dalvik/system/DexClassLoader");
    jclass clsMyDexClassLoader = env->FindClass("cn/yongye/nativeshell/inmemoryloaddex/MyDexClassLoader");
    jclass clsReference = env->FindClass("java/lang/ref/Reference");
    jclass clsClass = env->FindClass("java/lang/Class");


    jobject oCacheDir = env->CallObjectMethod(oApplication, env->GetMethodID(clsContextWrapper, "getCacheDir", "()Ljava/io/File;"));
    jstring stCacheDir = (jstring)env->CallObjectMethod(oCacheDir, env->GetMethodID(clsFile, "getAbsolutePath", "()Ljava/lang/String;"));


    jstring stCurrntPkgNa = static_cast<jstring>(env->CallObjectMethod(oApplication,
                                                                       env->GetMethodID(
                                                                               clsContextWrapper,
                                                                               "getPackageName","()Ljava/lang/String;")));
    jobject olibsFile = env->CallObjectMethod(oApplication, env->GetMethodID(clsContextWrapper, "getDir", "(Ljava/lang/String;I)Ljava/io/File;"), env->NewStringUTF("libs"), 0);
    jobject oParentDirPathFile = env->CallStaticObjectMethod(clsFileUtils, env->GetStaticMethodID(clsFileUtils, "getParent", "(Ljava/io/File;)Ljava/io/File;"), olibsFile);
    jobject oNativeLibFile = env->NewObject(clsFile, env->GetMethodID(clsFile, "<init>", "(Ljava/io/File;Ljava/lang/String;)V"), oParentDirPathFile, env->NewStringUTF("lib"));
    jstring stNativeLibFp = static_cast<jstring>(env->CallObjectMethod(oNativeLibFile,
                                                                       env->GetMethodID(clsFile,
                                                                                        "getAbsolutePath",
                                                                                        "()Ljava/lang/String;")));
    jobject oCurActivityThread = env->CallStaticObjectMethod(clsActivityThread, env->GetStaticMethodID(clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;"));
    jobject oMPkgs = env->GetObjectField(oCurActivityThread, env->GetFieldID(clsActivityThread, "mPackages", "Landroid/util/ArrayMap;"));
    jobject oWRShellLoadedApk = env->CallObjectMethod(oMPkgs, env->GetMethodID(clsMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;"), stCurrntPkgNa);
    jobject oShellLoadedApk = env->CallObjectMethod(oWRShellLoadedApk, env->GetMethodID(clsReference, "get", "()Ljava/lang/Object;"));


    jobject oSrcDexClassLoader = env->NewObject(clsMyDexClassLoader, env->GetMethodID(clsMyDexClassLoader, "<init>", "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"), ptSrcDex, env->GetObjectField(oShellLoadedApk, env->GetFieldID(clsLoadedApk, "mClassLoader", "Ljava/lang/ClassLoader;")));
    jobject mainadmin = env->CallObjectMethod(oSrcDexClassLoader, env->GetMethodID(clsMyDexClassLoader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"), env->NewStringUTF("com.h.MyAdmin"));
    jobject mainstring = env->CallObjectMethod(mainadmin, env->GetMethodID(clsClass, "toString", "()Ljava/lang/String;"));
    __android_log_write(ANDROID_LOG_WARN, "yongye", jstringToChar(env, (jstring)mainstring));
    __android_log_write(ANDROID_LOG_WARN, "yongye", jstringToChar(env, (jstring)mainstring));
//    jobject oSrcDexClassLoader = env->NewObject(clsDexLoader, env->GetMethodID(clsDexLoader, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"),
//                                                ptSrcDex, stCacheDir, stNativeLibFp, env->GetObjectField(oShellLoadedApk, env->GetFieldID(clsLoadedApk, "mClassLoader", "Ljava/lang/ClassLoader;")));

    //将原始DEX的classLoader替换进当前线程块中
    env->SetObjectField(oShellLoadedApk, env->GetFieldID(clsLoadedApk, "mClassLoader", "Ljava/lang/ClassLoader;"), oSrcDexClassLoader);
    __android_log_write(ANDROID_LOG_WARN, "yongye", "加载原始DEX完成");
}


void startSrcApplication(JNIEnv *env){
    __android_log_write(ANDROID_LOG_WARN, "yongye", "开始启动原始DEX的Application组件");
    jclass clsActivityThread = env->FindClass("android/app/ActivityThread");
    jclass clsConfig = env->FindClass("cn/yongye/nativeshell/common/Config");
    jclass clsAppBindData = env->FindClass("android/app/ActivityThread$AppBindData");
    jclass clsApplicationInfo = env->FindClass("android/content/pm/ApplicationInfo");
    jclass clsList = env->FindClass("java/util/List");
    jclass clsApplication = env->FindClass("android/app/Application");
    jclass clsLoadedApk = env->FindClass("android/app/LoadedApk");


    jobject oCurActivityThread = env->CallStaticObjectMethod(clsActivityThread, env->GetStaticMethodID(clsActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;"));
    jstring strSrcDexMainAppNa = (jstring)env->GetStaticObjectField(clsConfig, env->GetStaticFieldID(clsConfig, "MAIN_APPLICATION", "Ljava/lang/String;"));
    jobject mBoundApplication = env->GetObjectField(oCurActivityThread, env->GetFieldID(clsActivityThread, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;"));
    jobject oloadedApkInfo = env->GetObjectField(mBoundApplication, env->GetFieldID(clsAppBindData, "info", "Landroid/app/LoadedApk;"));
    env->SetObjectField(oloadedApkInfo, env->GetFieldID(clsLoadedApk, "mApplication", "Landroid/app/Application;"), nullptr);
    jobject omInitApplication = env->GetObjectField(oCurActivityThread, env->GetFieldID(clsActivityThread, "mInitialApplication", "Landroid/app/Application;"));
    jobject omAllApplications = env->GetObjectField(oCurActivityThread, env->GetFieldID(clsActivityThread, "mAllApplications", "Ljava/util/ArrayList;"));
    jboolean oRemoveRet = (jboolean)env->CallBooleanMethod(omAllApplications, env->GetMethodID(clsList, "remove", "(Ljava/lang/Object;)Z"), omInitApplication);
    jobject omApplicationInfo = env->GetObjectField(oloadedApkInfo, env->GetFieldID(clsLoadedApk, "mApplicationInfo", "Landroid/content/pm/ApplicationInfo;"));
    env->SetObjectField(omApplicationInfo, env->GetFieldID(clsApplicationInfo, "className", "Ljava/lang/String;"), strSrcDexMainAppNa);
    jobject oappInfo = env->GetObjectField(mBoundApplication, env->GetFieldID(clsAppBindData, "appInfo", "Landroid/content/pm/ApplicationInfo;"));
    env->SetObjectField(oappInfo, env->GetFieldID(clsApplicationInfo, "className", "Ljava/lang/String;"), strSrcDexMainAppNa);
    jobject omakeApplication = env->CallObjectMethod(oloadedApkInfo, env->GetMethodID(clsLoadedApk, "makeApplication", "(ZLandroid/app/Instrumentation;)Landroid/app/Application;"),
                                                     false, nullptr);
    env->SetObjectField(oCurActivityThread, env->GetFieldID(clsActivityThread, "mInitialApplication", "Landroid/app/Application;"), omakeApplication);
    env->CallVoidMethod(omakeApplication, env->GetMethodID(clsApplication, "onCreate", "()V"));
    __android_log_write(ANDROID_LOG_WARN, "yongye", "启动原始DEX Application完成");
}

/**
 * 加固：将加载原始DEX文件以及启动原始DEX的application在Native层实现
 */
extern "C"
JNIEXPORT void JNICALL
Java_cn_yongye_nativeshell_StubApp_loadDEX(JNIEnv *env, jobject app) {
    // TODO: implement loadDEX()
    /**
     * 第一步：从原APK中读取壳DEX
     */
    jbyteArray jbaShellDEX = readDexFileFromApk(env, app);

    /**
     * 第二步：内存解密原始DEX
     */
    jobjectArray strSrcDexFp = decyptSrcDex(env, app, jbaShellDEX);

    /**
     * 第三步：内存加载原始DEX
     */
     loadSrcDEX(env, app, strSrcDexFp);

     /**
      * 第四步：启动原始DEX的Application组件
      */
    startSrcApplication(env);
}






