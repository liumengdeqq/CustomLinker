//
//  public.h
//  goblin4.4.2
//
//  Created by liu meng on 2018/2/26.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

#ifndef public_h
#define public_h
#define FLAG_LINKED     0x00000001
#define FLAG_ERROR      0x00000002
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_LINKER     0x00000010 // The linker itself
#include <android/log.h>
#define LOG_TAG "liumeng"
#define SOINFO_NAME_LEN 128
enum RelocationKind {
    kRelocAbsolute = 0,
    kRelocRelative,
    kRelocCopy,
    kRelocSymbol,
    kRelocMax
};
#define MARK(x) do {} while (0)
#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
#if STATS
struct linker_stats_t {
    int count[kRelocMax];
};

static linker_stats_t linker_stats;

static void count_relocation(RelocationKind kind) {
    ++linker_stats.count[kind];
}
#else
static void count_relocation(RelocationKind) {
}
#endif

enum {
    RT_CONSISTENT,
    RT_ADD,
    RT_DELETE
};
#ifdef ANDROID_ARM_LINKER

#define R_ARM_COPY       20
#define R_ARM_GLOB_DAT   21
#define R_ARM_JUMP_SLOT  22
#define R_ARM_RELATIVE   23

/* According to the AAPCS specification, we only
 * need the above relocations. However, in practice,
 * the following ones turn up from time to time.
 */
#define R_ARM_ABS32      2
#define R_ARM_REL32      3

#elif defined(ANDROID_X86_LINKER)

#define R_386_32         1
#define R_386_PC32       2
#define R_386_GLOB_DAT   6
#define R_386_JUMP_SLOT  7
#define R_386_RELATIVE   8

#endif

#ifndef DT_INIT_ARRAY
#define DT_INIT_ARRAY      25
#endif

#ifndef DT_FINI_ARRAY
#define DT_FINI_ARRAY      26
#endif

#ifndef DT_INIT_ARRAYSZ
#define DT_INIT_ARRAYSZ    27
#endif

#ifndef DT_FINI_ARRAYSZ
#define DT_FINI_ARRAYSZ    28
#endif

#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif

#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif
#define format_buffer(b, s, f, p...) sprintf(b, f, p);
static const char *sopaths[] = {
        "/vendor/lib",
        "/system/lib",
        0
};
static int _open_lib(const char *name)
{
    int fd;
    struct stat filestat;

    if ((stat(name, &filestat) >= 0) && S_ISREG(filestat.st_mode)) {
        if ((fd = open(name,O_RDONLY | O_CLOEXEC)) >= 0)
            return fd;
    }

    return -1;
}

static int open_library(const char *name)
{
    int fd;
    char buf[512];
    const char **path;
    int n;
    if(name == 0) return -1;
    if(strlen(name) > 256) return -1;

    if ((name[0] == '/') && ((fd = _open_lib(name)) >= 0))
        return fd;


    for (path = sopaths; *path; path++) {
        n = format_buffer(buf, sizeof(buf), "%s/%s", *path, name);
        if (n < 0 || n >= (int)sizeof(buf)) {
            continue;
        }
        if ((fd = _open_lib(buf)) >= 0)
            return fd;
    }

    return -1;
}

#define DL_ERR(fmt, args...)    __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,fmt, ##args)
#define DEBUG(fmt, args...)    __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,fmt, ##args)
#define INFO(fmt, args...)    __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,fmt, ##args)

#endif /* public_h */
