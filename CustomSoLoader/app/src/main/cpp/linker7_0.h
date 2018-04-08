#ifndef _LINKER7_0_H_
#define _LINKER7_0_H_
#include <unistd.h>
#include <sys/types.h>
#include "elf.h"
#include "exec_elf.h"
#include "auxvec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <pthread.h>
#include <jni.h>
#include <sys/mman.h>
#include "public.h"

#define PAGE_S_SIZE 4096
#define PAGE_S_MASK (~(PAGE_S_SIZE-1))

// Returns the address of the page containing address 'x'.
#define PAGE_S_START(x) ((x) & PAGE_S_MASK)

#define PAGE_S_OFFSET(x) ((x) & ~PAGE_S_MASK)

#define PAGE_S_END(x) PAGE_S_START((x) + (PAGE_S_SIZE-1))
#ifndef __cplusplus
#define alignas _Alignas
#define alignof _Alignof
#endif
#if __LP64__
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

#ifdef __LP64__
typedef long           intptr_t;
typedef unsigned long  uintptr_t;
#else
typedef int           intptr_t;
typedef unsigned int  uintptr_t;
#endif

void* start_page_address7_0;
Elf32_Addr start_page_filelength7_0;
typedef struct soinfo7_0 soinfo7_0;
struct link_map_t7_0 {
  uintptr_t l_addr;
  char*  l_name;
  uintptr_t l_ld;
  struct link_map_t7_0* l_next;
  struct link_map_t7_0* l_prev;
};

typedef void (*linker_function_t7_0)();
struct soinfo7_0 {
  char name[SOINFO_NAME_LEN];
  const Elf32_Phdr* phdr;
  size_t phnum;
  Elf32_Addr entry;
  Elf32_Addr base;
  unsigned size;

  uint32_t unused1;  

  Elf32_Dyn* dynamic;

  uint32_t unused2; 
  uint32_t unused3; 

  soinfo7_0* next;
  unsigned flags;

  const char* strtab;
  Elf32_Sym* symtab;

  size_t nbucket;
  size_t nchain;
  unsigned* bucket;
  unsigned* chain;

  unsigned* plt_got;

  Elf32_Rel* plt_rel;
  size_t plt_rel_count;

  Elf32_Rel* rel;
  size_t rel_count;

  linker_function_t7_0* preinit_array;
  size_t preinit_array_count;

  linker_function_t7_0* init_array;
  size_t init_array_count;
  linker_function_t7_0* fini_array;
  size_t fini_array_count;

  linker_function_t7_0 init_func;
  linker_function_t7_0 fini_func;
#if defined(ANDROID_ARM_LINKER)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

  size_t ref_count_;
  struct link_map_t7_0 link_map_head;

  unsigned char constructors_called;
  Elf32_Addr load_bias;
    unsigned char has_text_relocations;
    unsigned char  has_DT_SYMBOLIC;
    size_t strtab_size_;
};
static const char ANDROID_LIBDL_STRTAB1[] =
        // 0000000 00011111 111112 22222222 2333333 3333444444444455555555556666666 6667777777777888888888899999 99999
        // 0123456 78901234 567890 12345678 9012345 6789012345678901234567890123456 7890123456789012345678901234 56789
        "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0android_update_LD_LIBRARY_PATH\0android_get_LD_LIBRARY_PATH\0dl_it"
                // 00000000001 1111111112222222222 3333333333444444444455555555556666666666777 777777788888888889999999999
                // 01234567890 1234567890123456789 0123456789012345678901234567890123456789012 345678901234567890123456789
                "erate_phdr\0android_dlopen_ext\0android_set_application_target_sdk_version\0android_get_application_tar"
                // 0000000000111111 111122222222223333333333 4444444444555555555566666 6666677 777777778888888888
                // 0123456789012345 678901234567890123456789 0123456789012345678901234 5678901 234567890123456789
                "get_sdk_version\0android_init_namespaces\0android_create_namespace\0dlvsym\0android_dlwarning\0"
#if defined(__arm__)
                // 290
                "dl_unwind_find_exidx\0"
#endif
;
static unsigned g_libdl_buckets1[1] = { 1 };
#if defined(__arm__)
static unsigned g_libdl_chains1[] = { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0 };
#else
static unsigned g_libdl_chains[] = { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0 };
#endif





soinfo7_0* find_library_internal7_0(const char* name);
void *lookup_in_library7_0(soinfo7_0 *si, const char *name);
#endif