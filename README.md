# 概况

本文目的：通过**内存加载DEX文件技术**，完成**一键DEX加固脚本**

# 使用说明

```powershell
python sheller.py -f xxx.apk
```

# 加固原理

和我的另一个项目[Native层DEX一键加固脚本](https://github.com/yongyecc/dexsheller)基本一样，只是多了一步，引入了内存加载DEX技术

# 一键加固脚本实现步骤

1. 准备原DEX加密算法以及隐藏位置（壳DEX尾部）

```python
        """
        1. 第一步：确定加密算法
        """
        inKey = 0xFF
        print("[*] 确定加密解密算法，异或: {}".format(str(inKey)))
```

2. 生成壳DEX。（壳Application动态加载原application中需要原application的name字段）

```python
        """
        2. 第二步：准备好壳App
        """
        # 反编译原apk
        decompAPK(fp)
        # 获取Applicaiton name并保存到壳App源码中
        stSrcDexAppName = getAppName(fp)
        save_appName(stSrcDexAppName)
        # 编译出壳DEX
        compileShellDex()
        print("[*] 壳App的class字节码文件编译为:shell.dex完成")
```

3. 修改原APK文件中的AndroidManifest.xml文件的applicationandroid:name字段，实现从壳application启动

```python
        """
        3. 第三步：修改原apk AndroidManifest.xml文件中的Application name字段为壳的Application name字段
        """
        # 替换壳Applicaiton name到原apk的AndroidManifest.xml内
        replaceTag(fp, "cn.yongye.nativeshell.StubApp")
        print("[*] 原apk文件AndroidManifest.xml中application的name字段替换为壳application name字段完成")
```

4. 加密原DEX到壳DEX尾部并将壳DEX替换到原APK中

```python
        """
        4. 替换原apk中的DEX文件为壳DEX
        """
        replaceSDexToShellDex(os.path.join(stCurrentPt, "result.apk"))
        print("[*] 壳DEX替换原apk包内的DEX文件完成")
```

5. 添加脱壳lib库到原apk中

```python
        """
        5. 添加脱壳lib库到原apk中
        """
        addLib("result.apk")
```

6. apk签名

```python
        """
        6. apk签名
        """
        signApk(os.path.join(stCurrentPt, "result.apk"), os.path.join(stCurrentPt, "demo.keystore"))
        print("[*] 签名完成，生成apk文件: {}".format(os.path.join(stCurrentPt, "result.apk")))
```

# 内存加载DEX

了解内存加载DEX文件内存加载技术之前，我们需要了解DEX文件加载这一过程。

**DEX文件加载过程：**即下面左图所示的API调用链就是加载过程。DEX文件加载的核心是最后一层，通过Native层函数传入DEX文件从而获取一个cookie值

所以我们要**实现内存加载DEX**的话，不仅需要自己重写这套DEX文件调用链，最主要的是寻找一个Native层API实现传入DEX文件字节流来获取cookie值，就是下面右图所示调用链，API即openMemory(4.3 ART虚拟机以后， 4.3及其以前Dalvik虚拟机用openDexFile([byte...)API)即可实现这样的功能

![内存加载DEX](/images/内存加载DEX.png)

Android 8以后BaseDexClassLoader类就有内存加载的能力，参考Android 8源码，已经加入了这样的接口，我们只需要将相关代码文件copy下来，将最底层的Native函数用openMemory替代即可

![image-20200415234950548](/images/image-20200415234950548.png)

## 自定义MyDexClassLoader

通过dlopen和dlsym的方法找到openMemory函数实现核心函数即可

```c++
JNICALL extern "C"
JNIEXPORT jlong JNICALL
Java_cn_yongye_inmemoryloaddex_DexFile_createCookieWithArray(JNIEnv *env, jclass clazz,
                                                             jbyteArray buf, jint start, jint end) {
    // TODO: implement createCookieWithArray()
    void *artlib =  fake_dlopen("/system/lib/libart.so", RTLD_LAZY);
    if(!artlib){
        exit(0);
    }
    org_artDexFileOpenMemory22 openMemory22 = (org_artDexFileOpenMemory22)fake_dlsym(artlib,
                                                                        "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_7OatFileEPS9_");

    if(!openMemory22){
        exit(0);
    }
    jbyte *bytes;
    char *pDex  = NULL;
    std::string location = "";
    std::string err_msg;


    bytes = env->GetByteArrayElements(buf, 0);
    int inDexLen = env->GetArrayLength(buf);
    pDex = new char[inDexLen + 1];
    memset(pDex, 0, inDexLen + 1);
    memcpy(pDex, bytes, inDexLen);
    pDex[inDexLen] = 0;
    env->ReleaseByteArrayElements(buf, bytes, 0);
    const Header *dex_header = reinterpret_cast<const Header *>(pDex);
    void *value = openMemory22((const unsigned char *)pDex, inDexLen, location, dex_header->checksum_, NULL, NULL, &err_msg);

    jlong cookie = replace_cookie(env, value, 22);
    return cookie;

}
```

还需要实现DEX加载器另外一个重要功能，即加载类的能力，这个功能本来也是需要Native函数实现的，这里我们可以通过反射调用DexFile类的defineClass方法(加载类的调用链是：findClass->defineClass)实现

```java
private Class defineClass(String name, ClassLoader loader, Object cookie,
                              DexFile dexFile, List<Throwable> suppressed) {
        Class result = null;
        try {
            Class clsDexFile = Class.forName("dalvik.system.DexFile");
            Method mdDefineClass = clsDexFile.getDeclaredMethod("defineClass", String.class, ClassLoader.class, long.class, List.class);
            mdDefineClass.setAccessible(true);
            result = (Class) mdDefineClass.invoke(null, name, loader, cookie, suppressed);
        } catch (NoClassDefFoundError e) {
            if (suppressed != null) {
                suppressed.add(e);
            }
        } catch (ClassNotFoundException e) {
            if (suppressed != null) {
                suppressed.add(e);
            }
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return result;
    }
```

# Cmake、ninja编译cpp文件

native层代码源文件在cpp目录下，可以直接调用cpp/build.bat一键编译批处理文件

## cmake生成ninja编译配置文件

```powershell
D:\Android\Sdk\cmake\3.10.2.4988404\bin\cmake.exe . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=D:\Android\Sdk\ndk\20.0.5594570\build\c make\android.toolchain.cmake -DANDROID_ABI=x86 -DANDROID_NDK=D:\Android\Sdk\ndk\20.0.5594570 -DANDROID_PLATFORM=android-16 -DCMAKE_ANDROID_ARCH_ABI=x86 -DCMAKE_ANDROID_NDK=D:\Android\Sdk\ndk\20.0.5594570 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_MAKE_PROGRAM=D:\Android\Sdk\cmake\3.10.2.4988404\bin\ninja.exe -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=16 -GNinja
```

## ninja生成so文件

只是修改cpp文件，直接运行ninja命令，不用重新用cmake生成ninja配置文件
如果有新cpp文件的增加删除，还是需要删除配置文件，重新运行cmake的

```powershell
D:\Android\Sdk\cmake\3.10.2.4988404\bin\ninja.exe
```

# 参考

【1】[Android中apk加固完善篇之内存加载dex方案实现原理(不落地方式加载)](http://www.520monkey.com/archives/629)

【2】[内存解密并加载DEX](https://github.com/woxihuannisja/Bangcle)

# 鼓励

![支付宝](/images/zfb.png)

![微信](/images/wx.png)
