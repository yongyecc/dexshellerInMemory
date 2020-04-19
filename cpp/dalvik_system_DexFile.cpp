#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <android/log.h>
#include <iostream>
#include <stdio.h>
#include <sys/mman.h>
#include <elf.h>
#include <android/log.h>
#include <asm/fcntl.h>
#include <fcntl.h>
#include <vector>
#include "dalvik_system_DexFile.h"
#include <vector>


#define TAG "yongye"

#define log_info(fmt,args...) __android_log_print(ANDROID_LOG_INFO, TAG, (const char *) fmt, ##args)
#define log_err(fmt,args...) __android_log_print(ANDROID_LOG_ERROR, TAG, (const char *) fmt, ##args)

#ifdef LOG_DBG
#define log_dbg //log_info
#else
#define log_dbg(...)
#endif


//#ifdef __arm__
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
//#else defined(__aarch64__)
//#define Elf_Ehdr Elf64_Ehdr
//#define Elf_Shdr Elf64_Shdr
//#define Elf_Sym  Elf64_Sym
//#endif

struct ctx {
    void *load_addr;
    void *dynstr;
    void *dynsym;
    int nsyms;
    off_t bias;
};



void *fake_dlopen(const char *libpath, int flags);
void *fake_dlsym(void *handle, const char *name);


typedef void *(*org_artDexFileOpenMemory22)(const uint8_t *base, size_t size,
                                            const std::string &location, uint32_t location_checksum,
                                            void *mem_map, const void *oat_file, std::string *error_msg);

jlong replace_cookie(JNIEnv *env, void *c_dex_cookie, int sdk_int);

JNICALL extern "C"
JNIEXPORT jlong JNICALL
Java_cn_yongye_nativeshell_inmemoryloaddex_DexFile_createCookieWithDirectBuffer(JNIEnv *env, jclass clazz,
                                                                    jobject buf, jint start,
                                                                    jint end) {
    // TODO: implement createCookieWithDirectBuffer()

}


JNICALL extern "C"
JNIEXPORT jlong JNICALL
Java_cn_yongye_nativeshell_inmemoryloaddex_DexFile_createCookieWithArray(JNIEnv *env, jclass clazz,
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



void *fake_dlsym(void *handle, const char *name)
{
    int k;
    struct ctx *ctx = (struct ctx *) handle;
    if(!ctx){
        exit(0);
    }
    Elf_Sym *sym = (Elf_Sym *) ctx->dynsym;
    char *strings = (char *) ctx->dynstr;

    for(k = 0; k < ctx->nsyms; k++, sym++)
        if(strcmp(strings + sym->st_name, name) == 0) {
            /*  NB: sym->st_value is an offset into the section for relocatables,
            but a VMA for shared libs or exe files, so we have to subtract the bias */
            void *ret = (char*)ctx->load_addr + sym->st_value - ctx->bias;
            //log_info("%s found at %p", name, ret);
            return ret;
        }
    return 0;
}

void *fake_dlopen(const char *libpath, int flags)
{
    FILE *maps;
    char buff[256];
    struct ctx *ctx = 0;
    off_t load_addr, size;
    int k, fd = -1, found = 0;
    char *shoff;
    Elf_Ehdr *elf = (Elf_Ehdr *)MAP_FAILED;

#define fatal(fmt,args...) do { ; goto err_exit; } while(0)

    maps = fopen("/proc/self/maps", "r");
    if(!maps) fatal("failed to open maps");

    while (fgets(buff, sizeof(buff), maps)) {
        if ((strstr(buff, "r-xp") || strstr(buff, "r--p")) && strstr(buff, libpath)) {
            found = 1;
            break;
        }
    }

    fclose(maps);

    if(!found) fatal("%s not found in my userspace", libpath);

    if(sscanf(buff, "%lx", &load_addr) != 1)
        fatal("failed to read load address for %s", libpath);

    //log_info("%s loaded in Android at 0x%08lx", libpath, load_addr);

    /* Now, mmap the same library once again */

    fd = open(libpath, O_RDONLY);
    if(fd < 0) fatal("failed to open %s", libpath);

    size = lseek(fd, 0, SEEK_END);
    if(size <= 0) fatal("lseek() failed for %s", libpath);

    elf = (Elf_Ehdr *) mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    fd = -1;

    if(elf == MAP_FAILED) fatal("mmap() failed for %s", libpath);

    ctx = (struct ctx *) calloc(1, sizeof(struct ctx));
    if(!ctx) fatal("no memory for %s", libpath);

    ctx->load_addr = (void *) load_addr;
    shoff = ((char* ) elf) + elf->e_shoff;

    for(k = 0; k < elf->e_shnum; k++, shoff += elf->e_shentsize)  {

        Elf_Shdr *sh = (Elf_Shdr *) shoff;
        log_dbg("%s: k=%d shdr=%p type=%x", __func__, k, sh, sh->sh_type);

        switch(sh->sh_type) {

            case SHT_DYNSYM:
                if(ctx->dynsym) fatal("%s: duplicate DYNSYM sections", libpath); /* .dynsym */
                ctx->dynsym = malloc(sh->sh_size);
                if(!ctx->dynsym) fatal("%s: no memory for .dynsym", libpath);
                memcpy(ctx->dynsym, ((char *) elf) + sh->sh_offset, sh->sh_size);
                ctx->nsyms = (sh->sh_size/sizeof(Elf_Sym)) ;
                break;

            case SHT_STRTAB:
                if(ctx->dynstr) break;	/* .dynstr is guaranteed to be the first STRTAB */
                ctx->dynstr = malloc(sh->sh_size);
                if(!ctx->dynstr) fatal("%s: no memory for .dynstr", libpath);
                memcpy(ctx->dynstr, ((char *) elf) + sh->sh_offset, sh->sh_size);
                break;

            case SHT_PROGBITS:
                if(!ctx->dynstr || !ctx->dynsym) break;
                /* won't even bother checking against the section name */
                ctx->bias = (off_t) sh->sh_addr - (off_t) sh->sh_offset;
                k = elf->e_shnum;  /* exit for */
                break;
        }
    }

    munmap(elf, size);
    elf = 0;

    if(!ctx->dynstr || !ctx->dynsym) fatal("dynamic sections not found in %s", libpath);

#undef fatal

    log_dbg("%s: ok, dynsym = %p, dynstr = %p", libpath, ctx->dynsym, ctx->dynstr);

    return ctx;

    err_exit:
    if(fd >= 0) close(fd);
    if(elf != MAP_FAILED) munmap(elf, size);
//    fake_dlclose(ctx);
    return 0;
}

jlong replace_cookie(JNIEnv *env, void *c_dex_cookie, int sdk_int) {
    if ((sdk_int == 21) || (sdk_int == 22)){
        std::unique_ptr<std::vector<const void *>> dex_files(new std::vector<const void *>());
        dex_files.get()->push_back(c_dex_cookie);
        jlong mCookie = static_cast<jlong>(reinterpret_cast<uintptr_t>(dex_files.release()));
        return mCookie;
    }

}
