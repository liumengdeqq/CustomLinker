#ifndef _SYS_DLOPEN_H_
#define _SYS_DLOPEN_H_
#include <unistd.h>
#include <sys/prctl.h>
#include "linker7_0.h"
#define SO_MAX 128
static int socount7_0 = 0;
static soinfo7_0 sopool7_0[SO_MAX];
static soinfo7_0 *freelist7_0 = NULL;
static off64_t kPageMasks = ~(PAGE_S_SIZE-1);
static off64_t page_s_start(off64_t offset) {
    return offset & kPageMasks;
}
static size_t page_s_offset(off64_t offset) {
    return (size_t)(offset & (PAGE_S_SIZE-1));
}
static int safe_s_add(off64_t* out, off64_t a, size_t b) {
    if ((uint64_t)(INT64_MAX - a) < b) {
        return 0;
    }
    *out = a + b;
    return 1;
}
/**
 * 计算so的内存最大地址和最小地址
 * @param phdr_table
 * @param phdr_count
 * @param out_min_vaddr
 * @return
 */
static size_t sys_phdr_table_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,ElfW(Addr)* out_min_vaddr) {
    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;
    int i;
    int found_pt_load = 0;
    for (i=0; i < phdr_count; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = 1;

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0;
    }
    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    min_vaddr = PAGE_S_START(min_vaddr);
    max_vaddr = PAGE_S_END(max_vaddr);
    return max_vaddr - min_vaddr;
}
/**
 * 获取so的基地址
 * @param name
 * @param first
 * @return
 */
static unsigned long get_sys_address(const char *name,unsigned long first){
    char *lpCh = NULL;
    char szLines[1024] = {0};
    unsigned long start = 0;
    unsigned  long tmp=0;
    FILE *fp = fopen("/proc/self/maps", "r");

    if (fp != NULL)
    {
        while (fgets(szLines, sizeof(szLines), fp))
        {
            if (strstr(szLines,name)&&strstr(szLines,"r-xp"))
            {

                DL_ERR("Find=%s",szLines);
                lpCh = strtok(szLines, "-");
                tmp=strtoul(lpCh, NULL, 16);
                if((start> tmp|| start ==0 )){
                    start=strtoul(lpCh, NULL, 16);
                }

            }
        }
        fclose(fp);
        return start;
    }
    else
    {
        DL_ERR("fopen error\r\n");
    }
    return -1;

}
/**
 * 获取dynamic段
 * @param phdr_table
 * @param phdr_count
 * @param load_bias
 * @param dynamic
 * @param dynamic_count
 * @param dynamic_flags
 */
static void sys_phdr_dynamic(const Elf32_Phdr* phdr_table,
                             int               phdr_count,
                             Elf32_Addr        load_bias,
                             Elf32_Dyn**       dynamic,
                             size_t*           dynamic_count,
                             Elf32_Word*       dynamic_flags)
{
    const Elf32_Phdr* phdr = phdr_table;
    const Elf32_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }
        *dynamic = (Elf32_Dyn*)(load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (unsigned)(phdr->p_memsz / 8);
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}
/**
 * 检测物理段结构体
 * @param loaded
 * @param fd_
 * @param name_
 * @param phdr_table_
 * @param phdr_num_
 * @param load_bias_
 * @return
 */
static Elf32_Phdr* sys_check_phdr( Elf32_Addr loaded,int fd_,const char *name_,const Elf32_Phdr* phdr_table_,size_t phdr_num_,Elf32_Addr load_bias_) {
     Elf32_Phdr* loaded_phdr_;
    const Elf32_Phdr* phdr;
    const Elf32_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    Elf32_Addr loaded_end = loaded + (phdr_num_ * sizeof(Elf32_Phdr));
    for ( phdr= phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
        Elf32_Addr seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ =(Elf32_Phdr*)loaded;
            return loaded_phdr_;
        }
    }
    DL_ERR("\"%s\" loaded phdr %x not in loadable segment", name_, loaded);
    return NULL;
}

/**
 * 获取物理段
 * @param fd_
 * @param name_
 * @param phdr_table_
 * @param phdr_num_
 * @param load_bias_
 * @return
 */
static Elf32_Phdr* sys_find_phdr(int fd_,const char *name_,const Elf32_Phdr* phdr_table_,size_t phdr_num_,Elf32_Addr load_bias_) {
    const Elf32_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    const Elf32_Phdr* phdr;
    for ( phdr= phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return sys_check_phdr(load_bias_ + phdr->p_vaddr,fd_,name_,phdr_table_,phdr_num_,load_bias_);
        }
    }
    for (phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                Elf32_Addr  elf_addr = load_bias_ + phdr->p_vaddr;
                const Elf32_Ehdr* ehdr = (const Elf32_Ehdr*)(void*)elf_addr;
                Elf32_Addr  offset = ehdr->e_phoff;
                return sys_check_phdr((Elf32_Addr)ehdr + offset,fd_,name_,phdr_table_,phdr_num_,load_bias_);
            }
            break;
        }
    }

    DL_ERR("can't find loaded phdr for \"%s\"", name_);
    return NULL;
}

/**
 * 创建soinfo结构体对象
 * @param name
 * @return
 */
static soinfo7_0 *sys_alloc_info(const char *name)
{
    soinfo7_0 *soinfo7_0=NULL;

    if(strlen(name) >= SOINFO_NAME_LEN) {
        DL_ERR("library name %s too long",name);
        return NULL;
    }
    if (!freelist7_0) {
        if(socount7_0 == SO_MAX) {
            DL_ERR("too many libraries when loading %s", name);
            return NULL;
        }
        freelist7_0 = sopool7_0 + socount7_0++;
        freelist7_0->next = NULL;
    }

    soinfo7_0 = freelist7_0;
    freelist7_0 = freelist7_0->next;
    DL_ERR("library name %s new ",name);
    memset(soinfo7_0, 0, sizeof(soinfo7_0));

    strlcpy((char*) soinfo7_0->name, name, sizeof(soinfo7_0->name));

    soinfo7_0->next = NULL;
    return soinfo7_0;
}
/**
 * 释放soinfo对象
 * @param si
 */
static void sys_free_info(soinfo7_0 *si)
{
    si->next = freelist7_0;
    freelist7_0 = si;
}
/**
 * 装在PT_DYNAMIC结构体数据
 * @param si
 * @return
 */
static int sys_link_image(soinfo7_0* si) {
    Elf32_Addr base = si->load_bias;
    const Elf32_Phdr *phdr = si->phdr;
    int phnum = si->phnum;
    int relocating_linker = (si->flags & FLAG_LINKER) ;
    if (!relocating_linker) {
        INFO("[ linking %s ]", si->name);
        DEBUG("si->base = 0x%08x si->flags = 0x%08x", si->base, si->flags);
    }
    size_t dynamic_count;
    Elf32_Word dynamic_flags;
    sys_phdr_dynamic(phdr, phnum, base, &si->dynamic,
                     &dynamic_count, &dynamic_flags);
    if (si->dynamic == NULL) {
        if (!relocating_linker) {
            DL_ERR("missing PT_DYNAMIC in \"%s\"", si->name);
        }
        return -1;
    } else {
        if (!relocating_linker) {
            DEBUG("dynamic = %p", si->dynamic);
        }
    }
#ifdef ANDROID_ARM_LINKER
    (void) phdr_table_get_arm_exidx4_4(phdr, phnum, base,
                                    &si->ARM_exidx, &si->ARM_exidx_count);
#endif
    uint32_t needed_count = 0;
    Elf32_Dyn* d;
    for (d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        DEBUG("d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x", d, d->d_tag, d->d_un.d_val);
        switch(d->d_tag){
            case DT_HASH:
                si->nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
                si->nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
                si->bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
                si->chain = (unsigned *) (base + d->d_un.d_ptr + 8 + si->nbucket * 4);
                break;
            case DT_STRTAB:
                si->strtab = (const char *) (base + d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si->symtab = (Elf32_Sym *) (base + d->d_un.d_ptr);
                break;
            case DT_PLTREL:
                if (d->d_un.d_val != DT_REL) {
                    DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                    return -1;
                }
                break;
            case DT_JMPREL:
                si->plt_rel = (Elf32_Rel*) (base + d->d_un.d_ptr);
                DL_ERR("plt_rel=%p",si->plt_rel);
                break;
            case DT_PLTRELSZ:
                si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                DL_ERR("plt_rel_count=%08x",si->plt_rel_count);
                break;
            case DT_REL:
                si->rel = (Elf32_Rel*) (base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                break;
            case DT_PLTGOT:
                si->plt_got = (unsigned *)(base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                break;
            case DT_RELA:
                DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                return -1;
            case DT_INIT:
                si->init_func = (void (*)(void))(base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_INIT) found at %p", si->name, si->init_func);
                break;
            case DT_FINI:
                si->fini_func = (void (*)(void))(base + d->d_un.d_ptr);
                DEBUG("%s destructors (DT_FINI) found at %p", si->name, si->fini_func);
                break;
            case DT_INIT_ARRAY:
                si->init_array = (unsigned *)(base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_INIT_ARRAY) found at %p", si->name, si->init_array);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_FINI_ARRAY:
                si->fini_array = (unsigned *)(base + d->d_un.d_ptr);
                DEBUG("%s destructors (DT_FINI_ARRAY) found at %p", si->name, si->fini_array);
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si->preinit_array = (unsigned *)(base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_PREINIT_ARRAY) found at %p", si->name, si->preinit_array);
                break;
            case DT_PREINIT_ARRAYSZ:
                si->preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_TEXTREL:
                si->has_text_relocations = 1;
                break;
            case DT_SYMBOLIC:
                si->has_DT_SYMBOLIC = 1;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
#if defined DT_FLAGS
                // TODO: why is DT_FLAGS not defined?
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
                    si->has_text_relocations = 1;
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    si->has_DT_SYMBOLIC = 1;
                }
                break;
#endif
#if defined(ANDROID_MIPS_LINKER)
            case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELENT:
             break;
        case DT_MIPS_RLD_MAP:
            // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
            {
              r_debug** dp = (r_debug**) d->d_un.d_ptr;
              *dp = &_r_debug;
            }
            break;
        case DT_MIPS_RLD_VERSION:
        case DT_MIPS_FLAGS:
        case DT_MIPS_BASE_ADDRESS:
        case DT_MIPS_UNREFEXTNO:
            break;

        case DT_MIPS_SYMTABNO:
            si->mips_symtabno = d->d_un.d_val;
            break;

        case DT_MIPS_LOCAL_GOTNO:
            si->mips_local_gotno = d->d_un.d_val;
            break;

        case DT_MIPS_GOTSYM:
            si->mips_gotsym = d->d_un.d_val;
            break;

        default:
            DEBUG("Unused DT entry: type 0x%08x arg 0x%08x", d->d_tag, d->d_un.d_val);
            break;
#endif
        }
    }

    DEBUG("si->base = 0x%08x, si->strtab = %p, si->symtab = %p",
          si->base, si->strtab, si->symtab);

    // Sanity checks.
    if (relocating_linker && needed_count != 0) {
        DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
        return -1;
    }
    if (si->nbucket == 0) {
        DL_ERR("empty/missing DT_HASH in \"%s\" (built with --hash-style=gnu?)", si->name);
        return -1;
    }
    if (si->strtab == 0) {
        DL_ERR("empty/missing DT_STRTAB in \"%s\"", si->name);
        return -1;
    }
    if (si->symtab == 0) {
        DL_ERR("empty/missing DT_SYMTAB in \"%s\"", si->name);
        return -1;
    }



    si->flags |= FLAG_LINKED;

    return 1;
}
/**
 * 获取so的根地址
 * @param fd_
 * @param name_
 * @param phdr_table_
 * @param phdr_num_
 * @param file_size_
 * @return
 */
static soinfo7_0*  sys_reserve_address_space(int fd_,const char* name_, const ElfW(Phdr)* phdr_table_,int  phdr_num_,off64_t file_size_){
    ElfW(Addr) min_vaddr=NULL;
    void* start;
    ElfW(Addr) load_bias_=NULL;
    const Elf32_Phdr* loaded_phdr_;
    const char *bname;
    soinfo7_0 *soinfos = NULL;
    size_t load_size_ = sys_phdr_table_size(phdr_table_, phdr_num_, &min_vaddr);
    if (load_size_ == 0) {
        DL_ERR("%s has no loadable segments", name_);
        return NULL;
    }
    DL_ERR("%s get_sys_address", name_);
    uint8_t* addr = (uint8_t*)(min_vaddr);
    unsigned long  address=get_sys_address(name_,-1);
    if(address==0){
        return NULL;
    }
    DL_ERR("soname---%s,address=%p",name_,address);
    start=(void*)address;
    load_bias_ = (uint8_t*)(start) - addr;
    loaded_phdr_=sys_find_phdr(fd_,name_,phdr_table_,phdr_num_,load_bias_);
    if(loaded_phdr_!=NULL){
        DL_ERR("findphdr success");
        bname = strrchr(name_, '/');
        DL_ERR("findphdr success %s",bname);
        soinfos = sys_alloc_info(bname ? bname + 1 : name_);
        if (soinfos == NULL){
            goto fail;
        }
        soinfos->flags = 0;
        soinfos->entry = 0;
        soinfos->dynamic =NULL;
        soinfos->phdr=loaded_phdr_;
        soinfos->load_bias=load_bias_;
        soinfos->phnum=phdr_num_;
        soinfos->base=(Elf32_Addr)start;
        soinfos->size=load_size_;
        DL_ERR("size---->>%08x",load_size_);
        if(sys_link_image(soinfos)==1){
            DL_ERR("soinfo_link_image7_0 success");
        }
        close(fd_);
        return soinfos;
        fail:
        DL_ERR("  alloc_info4_4 fail ");
        close(fd_);
    }
    return soinfos;
}

/**
 * 获取so的物理段结构体
 * @param fd
 * @param name_
 * @param base_offset
 * @param elf_offset
 * @param size
 * @return
 */
static  ElfW(Phdr)*  sys_phdr_map(int fd,const char *name_, off64_t base_offset, size_t elf_offset, size_t size) {
    off64_t offset;
    void* data_;
     ElfW(Phdr)* phdr_table_;
    safe_s_add(&offset, base_offset, elf_offset);
    off64_t page_min = page_s_start(offset);
    off64_t end_offset;
    safe_s_add(&end_offset, offset, size);
    safe_s_add(&end_offset, end_offset, page_s_offset(offset));
    size_t map_size = (size_t)(end_offset - page_min);
    uint8_t* map_start = (uint8_t*)(mmap64(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, page_min));
    if (map_start == MAP_FAILED) {
        DL_ERR("%s  phdr mmap PROT_READ failed: %s", name_, strerror(errno));
        return NULL;
    }
    data_ = map_start + page_s_offset(offset);
    phdr_table_ = (ElfW(Phdr)*) data_;
    return phdr_table_;
}


static int sys_get_target_elf_machine() {
#if defined(__arm__)
    return EM_ARM;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__i386__)
    return EM_386;
#elif defined(__mips__)
    return EM_MIPS;
#elif defined(__x86_64__)
  return EM_X86_64;
#endif
}
/**
 * 验证so文件的header
 * @param fd_
 * @param name_
 * @param header_
 * @param file_size_
 * @return
 */
static soinfo7_0* sys_verify_elf_header(int fd_,const char *name_,Elf32_Ehdr header_,off64_t file_size_) {
    size_t phdr_num_;
    off64_t file_offset_=0;

    if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
        DL_ERR("\"%s\" has bad ELF magic", name_);
        return NULL;
    }
    int elf_class = header_.e_ident[EI_CLASS];
    if (elf_class != ELFCLASS32) {
        DL_ERR("\"%s\" is 64-bit instead of 32-bit %08x", name_,elf_class);
        return NULL;
    }
    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        DL_ERR("\"%s\" not little-endian: %d", name_, header_.e_ident[EI_DATA]);
        return NULL;
    }

    if (header_.e_type != ET_DYN) {
        DL_ERR("\"%s\" has unexpected e_type: %d", name_, header_.e_type);
        return NULL;
    }

    if (header_.e_version != EV_CURRENT) {
        DL_ERR("\"%s\" has unexpected e_version: %d", name_, header_.e_version);
        return NULL;
    }

    if (header_.e_machine != sys_get_target_elf_machine()) {
        DL_ERR("\"%s\" has unexpected e_machine: %d", name_, header_.e_machine);
        return NULL;
    }
    phdr_num_ = header_.e_phnum;
    size_t size = phdr_num_ * sizeof(ElfW(Phdr));
    if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(ElfW(Phdr))) {
        DL_ERR("\"%s\" has invalid e_phnum: %zd", name_, phdr_num_);
        return NULL;
    }
    const ElfW(Phdr)* phdr_table_=sys_phdr_map(fd_,name_,file_offset_, header_.e_phoff, size);
    if (phdr_table_==NULL) {
        DL_ERR("\"%s\" phdr mmap failed: %s", name_, strerror(errno));
        return NULL;
    }
    soinfo7_0 * soinfo7_0= sys_reserve_address_space(fd_,name_,phdr_table_,phdr_num_,file_size_);
    if(soinfo7_0==NULL){
        DL_ERR("\"%s\"  ReserveAddressSpace7_0 failed: %s", name_, strerror(errno));
    }

    return soinfo7_0;
}
static soinfo7_0*  sys_read_elf_header(int fd_,const char *name_, off64_t file_size) {
    Elf32_Ehdr header_;
    size_t phdr_num_;
    int n;
    off64_t off64=0;
    ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd_, &header_, sizeof(header_),off64));
    if (rc < 0) {
        DL_ERR("can't read file \"%s\": %s", name_, strerror(errno));
        return NULL;
    }
    if (rc != sizeof(header_)) {
        DL_ERR("\"%s\" is too small to be an ELF executable", name_);
        return NULL;
    }
    soinfo7_0* soinfo=sys_verify_elf_header(fd_,name_,header_,file_size);
    if(soinfo!=NULL){
        DL_ERR("success1 %08x",phdr_num_);
    }else{
        DL_ERR("fail1 %08x",phdr_num_);
    }
    return soinfo;
}

static soinfo7_0 *sys_dlopen(const char *name){
    int fd = open_library(name);
    struct stat file_stat;
    unsigned long st_size;

    if (TEMP_FAILURE_RETRY(fstat(fd, &file_stat)) != 0) {
        DL_ERR("unable to stat file for the library \"%s\": %s", name, strerror(errno));
        return 0;
    }
    st_size=file_stat.st_size;
    soinfo7_0* soinfo=sys_read_elf_header(fd,name,st_size);
    if(soinfo!=NULL){
        DL_ERR("success");
    }else{
        DL_ERR("fail");
    }
    return soinfo;
}


#endif