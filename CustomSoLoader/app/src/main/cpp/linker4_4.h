#ifndef _LINKER4_4_H_
#define _LINKER4_4_H_
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
#include "elf_arm_const.h"
//#define PAGE_SHIFT 12
//#define PAGE_Y_SIZE (1UL << PAGE_SHIFT)
//#define PAGE_Y_MASK (~(PAGE_Y_SIZE-1))
#define PAGE_START(x)  ((x) & PAGE_MASK)
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#ifdef __LP64__
typedef long           intptr_t;
typedef unsigned long  uintptr_t;
#else
typedef int           intptr_t;
typedef unsigned int  uintptr_t;
#endif
typedef struct soinfo4_4 soinfo4_4;
struct link_map_4_4_t {
  uintptr_t l_addr;
  char*  l_name;
  uintptr_t l_ld;
  struct link_map_4_4_t* l_next;
  struct link_map_4_4_t* l_prev;
};
void* start_page_address4_4;
Elf32_Addr start_page_filelength4_4;
#define ANDROID_ARM_LINKER "arm"
typedef void (*linker_function4_4_t)();
struct soinfo4_4 {
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

  soinfo4_4* next;
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

  linker_function4_4_t* preinit_array;
  size_t preinit_array_count;

  linker_function4_4_t* init_array;
  size_t init_array_count;
  linker_function4_4_t* fini_array;
  size_t fini_array_count;

 linker_function4_4_t init_func;
  linker_function4_4_t fini_func;
#if defined(ANDROID_ARM_LINKER)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

  size_t ref_count;
  struct link_map_4_4_t link_map;

  unsigned char constructors_called;
  Elf32_Addr load_bias;
  unsigned char has_text_relocations;
  unsigned char has_DT_SYMBOLIC;
};
soinfo4_4* find_library_internal4_4(const char* name);
void *lookup_in_library4_4(soinfo4_4 *si, const char *name);
#endif