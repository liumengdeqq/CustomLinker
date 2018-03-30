//
//  exec_elf.h
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/1/30.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

#ifndef _SYS_EXEC_ELF_H_
#define _SYS_EXEC_ELF_H_

#include "types.h"
#include "exec.h"
#include "elf.h"

/* e_ident[] Operating System/ABI */
#define ELFOSABI_SYSV        0    /* UNIX System V ABI */
#define ELFOSABI_HPUX        1    /* HP-UX operating system */
#define ELFOSABI_NETBSD        2    /* NetBSD */
#define ELFOSABI_LINUX        3    /* GNU/Linux */
#define ELFOSABI_HURD        4    /* GNU/Hurd */
#define ELFOSABI_86OPEN        5    /* 86Open common IA32 ABI */
#define ELFOSABI_SOLARIS    6    /* Solaris */
#define ELFOSABI_MONTEREY    7    /* Monterey */
#define ELFOSABI_IRIX        8    /* IRIX */
#define ELFOSABI_FREEBSD    9    /* FreeBSD */
#define ELFOSABI_TRU64        10    /* TRU64 UNIX */
#define ELFOSABI_MODESTO    11    /* Novell Modesto */
#define ELFOSABI_OPENBSD    12    /* OpenBSD */
#define ELFOSABI_ARM        97    /* ARM */
#define ELFOSABI_STANDALONE    255    /* Standalone (embedded) application */

/* e_ident */
#define IS_ELF(ehdr) ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
(ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
(ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
(ehdr).e_ident[EI_MAG3] == ELFMAG3)

/* e_machine */
#define EM_NONE        0        /* No Machine */
#define EM_M32        1        /* AT&T WE 32100 */
#define EM_SPARC    2        /* SPARC */
#define EM_386        3        /* Intel 80386 */
#define EM_68K        4        /* Motorola 68000 */
#define EM_88K        5        /* Motorola 88000 */
#define EM_486        6        /* Intel 80486 - unused? */
#define EM_860        7        /* Intel 80860 */
#define EM_MIPS        8        /* MIPS R3000 Big-Endian only */
/*
 * Don't know if EM_MIPS_RS4_BE,
 * EM_SPARC64, EM_PARISC,
 * or EM_PPC are ABI compliant
 */
#define EM_MIPS_RS4_BE    10        /* MIPS R4000 Big-Endian */
#define EM_SPARC64    11        /* SPARC v9 64-bit unoffical */
#define EM_PARISC    15        /* HPPA */
#define EM_SPARC32PLUS    18        /* Enhanced instruction set SPARC */
#define EM_PPC        20        /* PowerPC */
#define EM_ARM        40        /* Advanced RISC Machines ARM */
#define EM_ALPHA    41        /* DEC ALPHA */
#define EM_SPARCV9    43        /* SPARC version 9 */
#define EM_ALPHA_EXP    0x9026        /* DEC ALPHA */
#define EM_AMD64    62        /* AMD64 architecture */
#define EM_VAX        75        /* DEC VAX */
#define EM_NUM        15        /* number of machine types */


/* Section names */
#define ELF_BSS         ".bss"        /* uninitialized data */
#define ELF_DATA        ".data"        /* initialized data */
#define ELF_DEBUG       ".debug"    /* debug */
#define ELF_DYNAMIC     ".dynamic"    /* dynamic linking information */
#define ELF_DYNSTR      ".dynstr"    /* dynamic string table */
#define ELF_DYNSYM      ".dynsym"    /* dynamic symbol table */
#define ELF_FINI        ".fini"        /* termination code */
#define ELF_GOT         ".got"        /* global offset table */
#define ELF_HASH        ".hash"        /* symbol hash table */
#define ELF_INIT        ".init"        /* initialization code */
#define ELF_REL_DATA    ".rel.data"    /* relocation data */
#define ELF_REL_FINI    ".rel.fini"    /* relocation termination code */
#define ELF_REL_INIT    ".rel.init"    /* relocation initialization code */
#define ELF_REL_DYN     ".rel.dyn"    /* relocaltion dynamic link info */
#define ELF_REL_RODATA  ".rel.rodata"    /* relocation read-only data */
#define ELF_REL_TEXT    ".rel.text"    /* relocation code */
#define ELF_RODATA      ".rodata"    /* read-only data */
#define ELF_SHSTRTAB    ".shstrtab"    /* section header string table */
#define ELF_STRTAB      ".strtab"    /* string table */
#define ELF_SYMTAB      ".symtab"    /* symbol table */
#define ELF_TEXT        ".text"        /* code */

/* Symbol Binding - ELF32_ST_BIND - st_info */
#define STB_LOCAL    0        /* Local symbol */
#define STB_GLOBAL    1        /* Global symbol */
#define STB_WEAK    2        /* like global - lower precedence */
#define STB_NUM        3        /* number of symbol bindings */
#define STB_LOPROC    13        /* reserved range for processor */
#define STB_HIPROC    15        /*  specific symbol bindings */

/* Symbol type - ELF32_ST_TYPE - st_info */
#define STT_NOTYPE    0        /* not specified */
#define STT_OBJECT    1        /* data object */
#define STT_FUNC    2        /* function */
#define STT_SECTION    3        /* section */
#define STT_FILE    4        /* file */
#define STT_NUM        5        /* number of symbol types */
#define STT_LOPROC    13        /* reserved range for processor */
#define STT_HIPROC    15        /*  specific symbol types */

#define PT_GNU_RELRO    0x6474e552      /* Read-only post relocation */

#endif /* _SYS_EXEC_ELF_H_ */

