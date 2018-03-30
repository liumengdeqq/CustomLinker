#include "linker7_0.h"
#include "linker4_4.h"
#include <sys/system_properties.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    // soinfo *si;
    DL_ERR("load start\n");

    //4.1.2  start
    // si = (soinfo *)gbdlopen("/data/local/tmp/libfoo.so",RTLD_NOW);
    // if(si!=NULL){
    //     DL_ERR("success");
    // }
    // xor_code(si->base);


    DL_ERR("-------%08x", sizeof(unsigned char));
    // jint (*real_JNI_OnLoad)(JavaVM*, void*);
    // real_JNI_OnLoad = (jint (*)(JavaVM*, void*))(gbdlsym(si,"JNI_OnLoad"));
    // if(real_JNI_OnLoad == NULL){
    //  DL_ERR("cannot find sym %s\n", "JNI_OnLoad");
    // }
    // return real_JNI_OnLoad(vm, reserved);
    //4.1.2 end
    char buf[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.sdk", buf);
    int version = 0;
    sscanf(buf, "%d", &version);
    if (version < 24) {
        //4.4 start
        soinfo4_4 *soinfo4_4 = find_library_internal4_4("/data/local/tmp/libfoo.so");
        if (soinfo4_4 == NULL) {
            DL_ERR("find soinfo fail");
        }
        DL_ERR("find soinfo success");
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
        soinfo7_0 *soinfo7_0 = find_library_internal7_0("/data/local/tmp/libfoo.so");
        if (soinfo7_0 == NULL) {
            DL_ERR("find soinfo fail");
        }
        DL_ERR("find soinfo success");
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
