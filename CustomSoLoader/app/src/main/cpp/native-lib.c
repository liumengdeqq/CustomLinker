#include "linker7_0.h"
#include "linker4_4.h"
#include "XorUtils.h"
#include <sys/system_properties.h>
#include <android/asset_manager_jni.h>


static void fix_cmdline(char *buf) {
    int length = strlen(buf);

    DL_ERR("length=%d", length);

    //TODO fix :remote bug
    while (length > -1) {
        if (buf[length] == ':') {
            buf[length] = '\0';
            break;
        }
        length--;
    }

}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {


    char buf[200];

    FILE *fp;
    int pid = getpid();
    sprintf(buf,"/proc/%d/cmdline", pid);
    fp = fopen(buf, "r");
    if(fp == NULL)
    {
        DL_ERR("Open error!!");
    }

    while(fgets(buf, sizeof(buf), fp)){
        DL_ERR("cmdline=%s", buf);
        fix_cmdline(buf);
        DL_ERR("cmdline=%s", buf);
    }
    fclose(fp);

    char desFile[400];
    sprintf(desFile, "/data/data/%s/lib/libdata.so", buf);
    DL_ERR("open file is %s", desFile);
    // jint (*real_JNI_OnLoad)(JavaVM*, void*);
    // real_JNI_OnLoad = (jint (*)(JavaVM*, void*))(gbdlsym(si,"JNI_OnLoad"));
    // if(real_JNI_OnLoad == NULL){
    //  DL_ERR("cannot find sym %s\n", "JNI_OnLoad");
    // }
    // return real_JNI_OnLoad(vm, reserved);
    //4.1.2 end

    __system_property_get("ro.build.version.sdk", buf);
    int version = 0;
    sscanf(buf, "%d", &version);
    if (version < 24) {
        //4.4 start
        soinfo4_4 *soinfo4_4 = find_library_internal4_4(desFile);
        if (soinfo4_4 == NULL) {
            DL_ERR("find soinfo fail");
            return JNI_VERSION_1_4;
        }
        DL_ERR("find soinfo success");

        xor_code(soinfo4_4->base,start_page_address4_4,start_page_filelength4_4);
        jint (*real_JNI_OnLoad4_4)(JavaVM *, void *);
        real_JNI_OnLoad4_4 = (jint (*)(JavaVM *, void *)) (lookup_in_library4_4(soinfo4_4,
                                                                                "JNI_OnLoad"));
        if (real_JNI_OnLoad4_4 == NULL) {
            DL_ERR("cannot find sym %s\n", "JNI_OnLoad");
        } else {
            return real_JNI_OnLoad4_4(vm, reserved);
        }
        //4.4 end
    } else {
        soinfo7_0 *soinfo7_0 = find_library_internal7_0(desFile);
        if (soinfo7_0 == NULL) {
            DL_ERR("find soinfo fail");
            return JNI_VERSION_1_4;
        }
        DL_ERR("find soinfo success");
        xor_code(soinfo7_0->base,start_page_address7_0,start_page_filelength7_0);
        jint (*real_JNI_OnLoad7_0)(JavaVM *, void *);
        real_JNI_OnLoad7_0 = (jint (*)(JavaVM *, void *)) (lookup_in_library7_0(soinfo7_0,
                                                                                "JNI_OnLoad"));
        if (real_JNI_OnLoad7_0 == NULL) {
            DL_ERR("cannot find sym %s\n", "JNI_OnLoad");
        } else {
            return real_JNI_OnLoad7_0(vm, reserved);
        }
        //7.0 end
    }
    return JNI_VERSION_1_4;
}
