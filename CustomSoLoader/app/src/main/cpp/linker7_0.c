#include "linker7_0.h"
#include "sys_dlopen.h"

static int socounts7_0 = 0;
static soinfo7_0 sopools7_0[128];
static soinfo7_0 *freelists7_0 = NULL;

static soinfo7_0 *alloc_info7_0(const char *name) {
    soinfo7_0 *soinfo7_0 = NULL;

    if (strlen(name) >= SOINFO_NAME_LEN) {
        DL_ERR("library name %s too long", name);
        return NULL;
    }
    if (!freelists7_0) {
        if (socounts7_0 == SO_MAX) {
            DL_ERR("too many libraries when loading %s", name);
            return NULL;
        }
        freelists7_0 = sopools7_0 + socounts7_0++;
        freelists7_0->next = NULL;
    }

    soinfo7_0 = freelists7_0;
    freelists7_0 = freelists7_0->next;
    DL_ERR("library name %s new ", name);
    memset(soinfo7_0, 0, sizeof(soinfo7_0));

    strlcpy((char *) soinfo7_0->name, name, sizeof(soinfo7_0->name));

    soinfo7_0->next = NULL;
    return soinfo7_0;
}

static void free_info7_0(soinfo7_0 *si) {
    si->next = freelists7_0;
    freelists7_0 = si;
}

static Elf32_Phdr *
CheckPhdr7_0(Elf32_Addr loaded, int fd_, const char *name_, const Elf32_Phdr *phdr_table_,
             size_t phdr_num_, Elf32_Addr load_bias_) {
    const Elf32_Phdr *loaded_phdr_;
    Elf32_Phdr *phdr;
    const Elf32_Phdr *phdr_limit = phdr_table_ + phdr_num_;
    Elf32_Addr loaded_end = loaded + (phdr_num_ * sizeof(Elf32_Phdr));
    for (phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
        Elf32_Addr seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = (Elf32_Phdr *) loaded;
            return loaded_phdr_;
        }
    }
    DL_ERR("\"%s\" loaded phdr %x not in loadable segment", name_, loaded);
    return NULL;
}

static Elf32_Phdr *
FindPhdr7_0(int fd_, const char *name_, const Elf32_Phdr *phdr_table_, size_t phdr_num_,
            Elf32_Addr load_bias_) {
    const Elf32_Phdr *phdr_limit = phdr_table_ + phdr_num_;
    const Elf32_Phdr *phdr;
    // If there is a PT_PHDR, use it directly.
    for (phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr7_0(load_bias_ + phdr->p_vaddr, fd_, name_, phdr_table_, phdr_num_,
                                load_bias_);
        }
    }
    for (phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                Elf32_Addr elf_addr = load_bias_ + phdr->p_vaddr;
                const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *) (void *) elf_addr;
                Elf32_Addr offset = ehdr->e_phoff;
                return CheckPhdr7_0((Elf32_Addr) ehdr + offset, fd_, name_, phdr_table_, phdr_num_,
                                    load_bias_);
            }
            break;
        }
    }

    DL_ERR("can't find loaded phdr for \"%s\"", name_);
    return NULL;
}

static soinfo7_0 *
LoadSegments7_0(int fd_, const char *name_, const Elf32_Phdr *phdr_table_, size_t phdr_num_,
                void *load_start_, Elf32_Addr load_size_, Elf32_Addr load_bias_) {
    size_t i;
    const Elf32_Phdr *loaded_phdr_;
    const char *bname;
    soinfo7_0 *soinfos = NULL;
    int count=0;
    for (i = 0; i < phdr_num_; ++i) {
        const Elf32_Phdr *phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        count++;
        // Segment addresses in memory.
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
        Elf32_Addr seg_end = seg_start + phdr->p_memsz;

        Elf32_Addr seg_page_start = PAGE_S_START(seg_start);
        Elf32_Addr seg_page_end = PAGE_S_END(seg_end);

        Elf32_Addr seg_file_end = seg_start + phdr->p_filesz;

        // File offsets.
        Elf32_Addr file_start = phdr->p_offset;
        Elf32_Addr file_end = file_start + phdr->p_filesz;

        Elf32_Addr file_page_start = PAGE_S_START(file_start);
        Elf32_Addr file_length = file_end - file_page_start;

        if (file_length != 0) {
            DL_ERR("seg_page_start==%08x. file_length=%08x", seg_page_start, file_length);
            void *seg_addr = mmap((void *) seg_page_start,
                                  file_length,
                                  PROT_WRITE | PROT_READ,
                                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                  0,
                                  0);
            if (seg_addr == MAP_FAILED) {
                DL_ERR("couldn't mmap1 \"%s\" segment %d: %s", name_, i, strerror(errno));
                return soinfos;
            }

            if (lseek(fd_, file_page_start, SEEK_SET) == -1L) {
                DL_ERR("couldn't lseek1 \"%s\" segment %d: %s", name_, i, strerror(errno));
                return soinfos;
            }

            if (-1 == read(fd_, seg_addr, file_length)) {
                DL_ERR("couldn't read \"%s\" segment %d: %s", name_, i, strerror(errno));
                return soinfos;
            }
            DL_ERR("LoadSegments seg_addr=%0x  flag=%08x", (unsigned) seg_addr,
                   PFLAGS_TO_PROT(phdr->p_flags));
            if(start_page_filelength7_0==0){
                start_page_address7_0=seg_addr;
                start_page_filelength7_0=file_length;
            }
            if (-1 == mprotect(seg_addr, file_length, PFLAGS_TO_PROT(phdr->p_flags))) {
                DL_ERR("couldn't mprotect \"%s\" segment %d: %s", name_, i, strerror(errno));
                return soinfos;
            }

            DL_ERR("LoadSegments succeed:%s!", name_);
        }
        if ((phdr->p_flags & PF_W) != 0 && PAGE_S_OFFSET(seg_file_end) > 0) {
            memset((void *) seg_file_end, 0, PAGE_S_SIZE - PAGE_S_OFFSET(seg_file_end));
        }

        seg_file_end = PAGE_S_END(seg_file_end);
        if (seg_page_end > seg_file_end) {
            void *zeromap = mmap((void *) seg_file_end,
                                 seg_page_end - seg_file_end,
                                 PFLAGS_TO_PROT(phdr->p_flags),
                                 MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                DL_ERR("couldn't zero fill \"%s\" gap: %s", name_, strerror(errno));
                return soinfos;
            }
        }
    }
    loaded_phdr_ = FindPhdr7_0(fd_, name_, phdr_table_, phdr_num_, load_bias_);
    if (loaded_phdr_ != NULL) {
        DL_ERR("findphdr success");
        bname = strrchr(name_, '/');
        DL_ERR("findphdr success %s", bname);
        soinfos = alloc_info7_0(bname ? bname + 1 : name_);
        if (soinfos == NULL) {
            goto fail;
        }
        soinfos->flags = 0;
        soinfos->entry = 0;

        soinfos->dynamic = (unsigned *) -1;
        soinfos->phdr = loaded_phdr_;
        soinfos->load_bias = load_bias_;
        soinfos->phnum = phdr_num_;
        // soinfos->base1=load_start_;
        soinfos->base = load_start_;
        soinfos->size = load_size_;
        DL_ERR("base1----->>%08x ,size---->>%08x", load_start_, load_size_);
        close(fd_);
        return soinfos;
        fail:
        DL_ERR("  alloc_info4_4 fail ");
        close(fd_);
    }
    return soinfos;
}

static size_t phdr_table_get_load_size7_0(const Elf32_Phdr *phdr_table,
                                          size_t phdr_count,
                                          Elf32_Addr *out_min_vaddr,
                                          Elf32_Addr *out_max_vaddr) {
    Elf32_Addr min_vaddr = 0xFFFFFFFFU;
    Elf32_Addr max_vaddr = 0x00000000U;
    size_t i;
    int found_pt_load = -1;
    for (i = 0; i < phdr_count; ++i) {
        const Elf32_Phdr *phdr = &phdr_table[i];

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
    if (found_pt_load != 1) {
        min_vaddr = 0x00000000U;
    }

    min_vaddr = PAGE_S_START(min_vaddr);
    max_vaddr = PAGE_S_END(max_vaddr);
    DL_ERR(" min=%08x,max=%08x", min_vaddr, max_vaddr);
    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != NULL) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}

static soinfo7_0 *ReserveAddressSpace7_0(int fd_, const char *name_, const Elf32_Phdr *phdr_table_,
                                         size_t phdr_num_) {
    Elf32_Addr min_vaddr;
    Elf32_Addr max_vaddr;
    Elf32_Addr load_size_;
    Elf32_Addr load_bias_;
    soinfo7_0 *soinfo = NULL;
    void *load_start_;
    load_size_ = phdr_table_get_load_size7_0(phdr_table_, phdr_num_, &min_vaddr, &max_vaddr);
    if (load_size_ == 0) {
        DL_ERR("\"%s\" has no loadable segments", name_);
        return soinfo;
    }
    uint8_t *addr = (uint8_t *) min_vaddr;
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *start = mmap(addr, load_size_, PROT_NONE, mmap_flags, -1, 0);
    if (start == MAP_FAILED) {
        DL_ERR("couldn't reserve %d bytes of address space for \"%s\"", load_size_, name_);
        return soinfo;
    }
    load_start_ = start;
    load_bias_ = (uint8_t *) start - addr;
    DL_ERR("load_start %p,load_bias %p", load_start_, load_bias_);
    soinfo = LoadSegments7_0(fd_, name_, phdr_table_, phdr_num_, load_start_, load_size_,
                             load_bias_);
    if (soinfo != NULL) {
        DL_ERR("load segments success");
    } else {
        DL_ERR("load segments error");
    }
    return soinfo;
}

static int VerifyElfHeader7_0(const char *name_, Elf32_Ehdr header_) {
    if (header_.e_ident[EI_MAG0] != ELFMAG0 ||
        header_.e_ident[EI_MAG1] != ELFMAG1 ||
        header_.e_ident[EI_MAG2] != ELFMAG2 ||
        header_.e_ident[EI_MAG3] != ELFMAG3) {
        DL_ERR("\"%s\" has bad ELF magic", name_);
        return -1;
    }

    if (header_.e_ident[EI_CLASS] != ELFCLASS32) {
        DL_ERR("\"%s\" not 32-bit: %d", name_, header_.e_ident[EI_CLASS]);
        return -1;
    }
    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        DL_ERR("\"%s\" not little-endian: %d", name_, header_.e_ident[EI_DATA]);
        return -1;
    }

    if (header_.e_type != ET_DYN) {
        DL_ERR("\"%s\" has unexpected e_type: %d", name_, header_.e_type);
        return -1;
    }

    if (header_.e_version != EV_CURRENT) {
        DL_ERR("\"%s\" has unexpected e_version: %d", name_, header_.e_version);
        return -1;
    }

    if (header_.e_machine != EM_ARM) {
        DL_ERR("\"%s\" has unexpected e_machine: %d", name_, header_.e_machine);
        return -1;
    }
    DL_ERR("verify elf success");
    return 1;
}

static soinfo7_0 *
ReadProgramHeader7_0(int fd_, const char *name_, Elf32_Ehdr header_, size_t phdr_num_) {
    Elf32_Addr phdr_size_;
    Elf32_Phdr *phdr_table_;
    soinfo7_0 *soinfo = NULL;
    if (phdr_num_ < 1 || phdr_num_ > 65536 / sizeof(Elf32_Phdr)) {
        DL_ERR("\"%s\" has invalid e_phnum: %d", name_, phdr_num_);
        return soinfo;
    }
    Elf32_Addr page_min = PAGE_S_START(header_.e_phoff);
    Elf32_Addr page_max = PAGE_S_END(header_.e_phoff + (phdr_num_ * sizeof(Elf32_Phdr)));
    Elf32_Addr page_offset = PAGE_S_OFFSET(header_.e_phoff);
    DL_ERR("page_min  --->>>%08x,page_max  --->>>%08x", page_min, page_max);
    phdr_size_ = page_max - page_min;
    DL_ERR("phdr_size_  --->>>%08x", phdr_size_);
    void *mmap_result = mmap(NULL, phdr_size_, PROT_READ, MAP_PRIVATE, fd_, page_min);
    if (mmap_result == MAP_FAILED) {
        DL_ERR("\"%s\" phdr mmap failed: %s", name_, strerror(errno));
        return soinfo;
    }
    if (VerifyElfHeader7_0(name_, header_) != 1) {
        DL_ERR("verify elf fail");
        return soinfo;
    }
    phdr_table_ = (Elf32_Phdr *) ((char *) mmap_result + page_offset);
    soinfo = ReserveAddressSpace7_0(fd_, name_, phdr_table_, phdr_num_);
    if (soinfo != NULL) {
        DL_ERR("reserve address success");
    }
    return soinfo;

}

static soinfo7_0 *ReadElfHeader7_0(int fd_, const char *name_) {
    Elf32_Ehdr header_;
    size_t phdr_num_;
    ssize_t rc = TEMP_FAILURE_RETRY(read(fd_, &header_, sizeof(header_)));
    phdr_num_ = header_.e_phnum;
    DL_ERR("\"%s\" is e_phnum: %d", name_, phdr_num_);
    if (rc < 0) {
        DL_ERR("can't read file \"%s\": %s", name_, strerror(errno));
        return NULL;
    }
    if (rc != sizeof(header_)) {
        DL_ERR("\"%s\" is too small to be an ELF executable", name_);
        return NULL;
    }
    soinfo7_0 *soinfo = ReadProgramHeader7_0(fd_, name_, header_, phdr_num_);
    if (soinfo != NULL) {
        DL_ERR("success1 %08x", phdr_num_);
    } else {
        DL_ERR("fail1 %08x", phdr_num_);
    }
    return soinfo;
}

static void phdr_table_get_dynamic_section7_0(const Elf32_Phdr *phdr_table,
                                              int phdr_count,
                                              Elf32_Addr load_bias,
                                              Elf32_Dyn **dynamic,
                                              size_t *dynamic_count,
                                              Elf32_Word *dynamic_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        *dynamic = (Elf32_Dyn *) (load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (unsigned) (phdr->p_memsz / 8);
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

static int
_phdr_table_set_load_prot7_0(const Elf32_Phdr *phdr_table,
                             int phdr_count,
                             Elf32_Addr load_bias,
                             int extra_prot_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0)
            continue;

        Elf32_Addr seg_page_start = PAGE_S_START(phdr->p_vaddr) + load_bias;
        Elf32_Addr seg_page_end = PAGE_S_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;
        DL_ERR("segments ------=%08x", seg_page_start);
        int ret = mprotect((void *) seg_page_start,
                           seg_page_end - seg_page_start,
                           PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

int
phdr_table_protect_segments7_0(const Elf32_Phdr *phdr_table,
                               int phdr_count,
                               Elf32_Addr load_bias) {
    return _phdr_table_set_load_prot7_0(phdr_table, phdr_count,
                                        load_bias, 0);
}

int
phdr_table_unprotect_segments7_0(const Elf32_Phdr *phdr_table,
                                 int phdr_count,
                                 Elf32_Addr load_bias) {
    return _phdr_table_set_load_prot7_0(phdr_table, phdr_count,
                                        load_bias, PROT_WRITE);
}

static int
_phdr_table_set_gnu_relro_prot7_0(const Elf32_Phdr *phdr_table,
                                  int phdr_count,
                                  Elf32_Addr load_bias,
                                  int prot_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_GNU_RELRO)
            continue;
        Elf32_Addr seg_page_start = PAGE_S_START(phdr->p_vaddr) + load_bias;
        Elf32_Addr seg_page_end = PAGE_S_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;
        DL_ERR("_phdr_table_set_gnu_relro_prot GNU=%08x", seg_page_start);
        int ret = mprotect((void *) seg_page_start,
                           seg_page_end - seg_page_start,
                           prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

int
phdr_table_protect_gnu_relro7_0(const Elf32_Phdr *phdr_table,
                                int phdr_count,
                                Elf32_Addr load_bias) {
    return _phdr_table_set_gnu_relro_prot7_0(phdr_table,
                                             phdr_count,
                                             load_bias,
                                             PROT_READ);
}

static Elf32_Sym *soinfo_elf_lookup7_0(soinfo7_0 *si, unsigned hash, const char *name) {
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    unsigned n = 0;
    DL_ERR("SEARCH %s in %s@0x%08x %08x %d=====%08x",
           name, si->name, si->base, hash, hash % si->nbucket, si->nbucket);

    for (n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
        Elf32_Sym *s = symtab + n;
        // DL_ERR("NAME %s",strtab + s->st_name);
        if (strcmp(strtab + s->st_name, name)) continue;

        /* only concern ourselves with global and weak symbol definitions */
        switch (ELF32_ST_BIND(s->st_info)) {
            case STB_GLOBAL:
            case STB_WEAK:
                if (s->st_shndx == SHN_UNDEF) {
                    continue;
                }

                DL_ERR("FOUND %s in %s (%08x) %d",
                       name, si->name, s->st_value, s->st_size);
                return s;
        }
    }
    // DL_ERR("NULL");

    return NULL;
}

static unsigned elfhash7_0(const char *_name) {
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

static Elf32_Sym *
soinfo_do_lookup7_0(soinfo7_0 *si, const char *name, soinfo7_0 **lsi, soinfo7_0 *needed[]) {
    unsigned elf_hash = elfhash7_0(name);
    Elf32_Sym *s = NULL;
    int i;
    for (i = 0; needed[i] != NULL; i++) {
        DEBUG("%s: looking up %s in %s",
              si->name, name, needed[i]->name);
        s = soinfo_elf_lookup7_0(needed[i], elf_hash, name);
        if (s != NULL) {
            *lsi = needed[i];
            goto done;
        }
    }

    done:
    if (s != NULL) {
        DL_ERR("si %s sym %s s->st_value = 0x%08x, "
                       "found in %s, base = 0x%08x, load bias = 0x%08x",
               si->name, name, s->st_value,
               (*lsi)->name, (*lsi)->base, (*lsi)->load_bias);
        return s;
    }

    return NULL;
}

static int soinfo_relocate7_0(soinfo7_0 *si, Elf32_Rel *rel, unsigned count,
                              soinfo7_0 *needed[]) {
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    Elf32_Sym *s;
    Elf32_Rel *start = rel;
    soinfo7_0 *lsi;
    size_t idx;

    for (idx = 0; idx < count; ++idx, ++rel) {
        unsigned type = ELF32_R_TYPE(rel->r_info);
        unsigned sym = ELF32_R_SYM(rel->r_info);
        Elf32_Addr reloc = (Elf32_Addr) (rel->r_offset + si->load_bias);
        Elf32_Addr sym_addr = 0;
        char *sym_name = NULL;

        DEBUG("Processing '%s' relocation at index %d", si->name, idx);
        if (type == 0) { // R_*_NONE
            continue;
        }
        if (sym != 0) {
            sym_name = (char *) (strtab + symtab[sym].st_name);
            s = soinfo_do_lookup7_0(si, sym_name, &lsi, needed);

            if (s == NULL) {

                /* We only allow an undefined symbol if this is a weak
                   reference..   */
                s = &symtab[sym];
                if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                    DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name,
                           si->name);
                    return -1;
                }
                if (s != NULL) {
                    DL_ERR(" %s is not null", sym_name);
                }
                switch (type) {
                    case 22:
                        DL_ERR("unknown weak reloc type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                    case 21:
                        DL_ERR("unknown weak reloc type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                    case 2:
                        DL_ERR("unknown weak reloc type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                    case 23:
                        DL_ERR("unknown weak reloc type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                        break;
                    case 20:
                        DL_ERR("unknown weak reloc type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                    default:
                        DL_ERR("unknown weak reloc error type %d @ %p (%d)",
                               type, rel, (int) (rel - start));
                        return -1;
                }
            } else {
                // if(lsi->load_bias!=NULL){
                //     lsi->base=lsi->load_bias;
                //  }
                sym_addr = (Elf32_Addr) (s->st_value + lsi->base);
            }
//            count_relocation(kRelocSymbol);
        } else {
            s = NULL;
        }

/* TODO: This is ugly. Split up the relocations by arch into
 * different files.
 */
        switch (type) {
            case 22:

                DL_ERR("RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;
            case 21:

                DL_ERR("RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;
            case 2:

                DL_ERR("RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
                *((Elf32_Addr *) reloc) += sym_addr;
                break;
            case 3:

                DL_ERR("RELO REL32 %08x <- %08x - %08x %s",
                       reloc, sym_addr, rel->r_offset, sym_name);
                *((Elf32_Addr *) reloc) += sym_addr - rel->r_offset;
                break;
            case 7:

                DL_ERR("RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;
            case 6:

                DL_ERR("RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;


            case 23:
//            count_relocation(kRelocRelative);
                MARK(rel->r_offset);
                if (sym) {
                    DL_ERR("odd RELATIVE form...");
                    return -1;
                }
                DL_ERR("RELO RELATIVE %08x <- +%08x", reloc, si->base);
                *((Elf32_Addr *) reloc) += si->base;
                break;

#

            case 20:
                if ((si->flags & FLAG_EXE) == 0) {

                    DL_ERR("%s R_ARM_COPY relocations only supported for ET_EXEC", si->name);
                    return -1;
                }

                DL_ERR("RELO %08x <- %d @ %08x %s", reloc, s->st_size, sym_addr, sym_name);
                if (reloc == sym_addr) {
                    Elf32_Sym *src = soinfo_do_lookup7_0(NULL, sym_name, &lsi, needed);

                    if (src == NULL) {
                        DL_ERR("%s R_ARM_COPY relocation source cannot be resolved", si->name);
                        return -1;
                    }
                    if (lsi->has_DT_SYMBOLIC) {
                        DL_ERR("%s invalid R_ARM_COPY relocation against DT_SYMBOLIC shared "
                                       "library %s (built with -Bsymbolic?)", si->name, lsi->name);
                        return -1;
                    }
                    if (s->st_size < src->st_size) {
                        DL_ERR("%s R_ARM_COPY relocation size mismatch (%d < %d)",
                               si->name, s->st_size, src->st_size);
                        return -1;
                    }
                    memcpy((void *) reloc, (void *) (src->st_value + lsi->load_bias), src->st_size);
                } else {
                    DL_ERR("%s R_ARM_COPY relocation target cannot be resolved", si->name);
                    return -1;
                }
                break;


            default:
                DL_ERR("unknown reloc type %d @ %p (%d)",
                       type, rel, (int) (rel - start));
                return -1;
        }
    }
    return 1;
}

static const char *select_sys_lib(const char *name) {
    if (strcmp(name, "libc.so") == 0) {
        return "/system/lib/libc.so";
    }
    if (strcmp(name, "libz.so") == 0) {
        return "/system/lib/libz.so";
    }
    if (strcmp(name, "liblog.so") == 0) {
//        return "/vendor/lib/liblog.so";
        return "/system/lib/liblog.so";
    }
    if (strcmp(name, "libm.so") == 0) {
        return "/system/lib/libm.so";
    }
//    if(strcmp(name,"libdl.so")==0){
//        return "/system/lib/libdl.so";
//    }
    if (strcmp(name, "libstdc++.so") == 0) {
        return "/system/lib/libstdc++.so";
    }
    return NULL;
}

static const char *select_vendor_lib(const char *name) {
    if (strcmp(name, "libc.so") == 0) {
        return "/vendor/lib/libc.so";
    }

    if (strcmp(name, "liblog.so") == 0) {
//        return "/vendor/lib/liblog.so";
        return "/vendor/lib/liblog.so";
    }
    if (strcmp(name, "libm.so") == 0) {
        return "/vendor/lib/libm.so";
    }

    if (strcmp(name, "libz.so") == 0) {
        return "/vendor/lib/libz.so";
    }
//    if(strcmp(name,"libdl.so")==0){
//        return "/system/lib/libdl.so";
//    }
    if (strcmp(name, "libstdc++.so") == 0) {
        return "/vendor/lib/libstdc++.so";
    }
    return NULL;
}


static Elf32_Sym libdl_symtab1[] = {
        // total length of libdl_info.strtab, including trailing 0
        // This is actually the the STH_UNDEF entry. Technically, it's
        // supposed to have st_name == 0, but instead, it points to an index
        // in the strtab with a \0 to make iterating through the symtab easier.
        {st_name: sizeof(ANDROID_LIBDL_STRTAB1) - 1,
        },
        {st_name: 0,   // starting index of the name in libdl_info.strtab
                st_value: (Elf32_Addr) &dlopen,
                st_info: STB_GLOBAL << 4,
                st_shndx: 1,
        },
        {st_name: 7,
                st_value: (Elf32_Addr) &dlclose,
                st_info: STB_GLOBAL << 4,
                st_shndx: 1,
        },
        {st_name: 15,
                st_value: (Elf32_Addr) &dlsym,
                st_info: STB_GLOBAL << 4,
                st_shndx: 1,
        },
        {st_name: 21,
                st_value: (Elf32_Addr) &dlerror,
                st_info: STB_GLOBAL << 4,
                st_shndx: 1,
        },
        {st_name: 29,
                st_value: (Elf32_Addr) &dladdr,
                st_info: STB_GLOBAL << 4,
                st_shndx: 1,
        }
};


soinfo7_0 libdl_info1 = {
        name: "libdl.so",
        flags: FLAG_LINKED,
        strtab: ANDROID_LIBDL_STRTAB1,
        symtab: libdl_symtab1,

        nbucket: sizeof(g_libdl_buckets1) / sizeof(unsigned),
        nchain: sizeof(g_libdl_buckets1) / sizeof(unsigned),
        bucket: g_libdl_buckets1,
        chain: g_libdl_chains1,
        ref_count_:1,
        strtab_size_:sizeof(ANDROID_LIBDL_STRTAB1),

};

static int soinfo_link_image7_0(soinfo7_0 *si) {
    /* "base" might wrap around UINT32_MAX. */
    Elf32_Addr base = si->load_bias;
    const Elf32_Phdr *phdr = si->phdr;
    int phnum = si->phnum;
    int relocating_linker = (si->flags & FLAG_LINKER);

    /* We can't debug anything until the linker is relocated */
    if (!relocating_linker) {
        INFO("[ linking %s ]", si->name);
        DEBUG("si->base = 0x%08x si->flags = 0x%08x", si->base, si->flags);
    }

    /* Extract dynamic section */
    size_t dynamic_count;
    Elf32_Word dynamic_flags;
    phdr_table_get_dynamic_section7_0(phdr, phnum, base, &si->dynamic,
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
    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    Elf32_Dyn *d;
    for (d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        DEBUG("d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x", d, d->d_tag, d->d_un.d_val);
        switch (d->d_tag) {
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
                si->plt_rel = (Elf32_Rel *) (base + d->d_un.d_ptr);
                DL_ERR("plt_rel=%p", si->plt_rel);
                break;
            case DT_PLTRELSZ:
                si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                DL_ERR("plt_rel_count=%08x", si->plt_rel_count);
                break;
            case DT_REL:
                si->rel = (Elf32_Rel *) (base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si->plt_got = (unsigned *) (base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                /*
                if ((dynamic_flags & PF_W) != 0) {
                    d->d_un.d_val = (int) &_r_debug;
                }*/
                break;
            case DT_RELA:
                DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                return -1;
            case DT_INIT:
                si->init_func = (void (*)(void)) (base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_INIT) found at %p", si->name, si->init_func);
                break;
            case DT_FINI:
                si->fini_func = (void (*)(void)) (base + d->d_un.d_ptr);
                DEBUG("%s destructors (DT_FINI) found at %p", si->name, si->fini_func);
                break;
            case DT_INIT_ARRAY:
                si->init_array = (unsigned *) (base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_INIT_ARRAY) found at %p", si->name, si->init_array);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_FINI_ARRAY:
                si->fini_array = (unsigned *) (base + d->d_un.d_ptr);
                DEBUG("%s destructors (DT_FINI_ARRAY) found at %p", si->name, si->fini_array);
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si->preinit_array = (unsigned *) (base + d->d_un.d_ptr);
                DEBUG("%s constructors (DT_PREINIT_ARRAY) found at %p", si->name,
                      si->preinit_array);
                break;
            case DT_PREINIT_ARRAYSZ:
                si->preinit_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
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
    soinfo7_0 **needed = (soinfo7_0 **) alloca((1 + needed_count) * sizeof(soinfo7_0 *));
    soinfo7_0 **pneeded = needed;
    // Elf32_Dyn* dd;
    for (d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            soinfo7_0 *lsi = NULL;
            const char *library_name = si->strtab + d->d_un.d_val;
            DEBUG("%s needs %s", si->name, library_name);
            if (strcmp(library_name, "libdl.so") == 0) {
                lsi = &libdl_info1;
            }
            const char *soname = select_sys_lib(library_name);
            if (soname != NULL) {
                lsi = sys_dlopen(soname);
                if (lsi == NULL) {
                    soname = select_vendor_lib(library_name);
                    if (soname != NULL) {
                        lsi = sys_dlopen(soname);
                    }
                }
            }
            if (lsi == NULL) {
                // strlcpy(tmp_err_buf, linker_get_error_buffer(), sizeof(tmp_err_buf));
                DL_ERR("could not load library \"%s\" needed by \"%s\"; caused by ",
                       library_name, si->name);
                return -1;
            } else {
                *pneeded++ = lsi;
            }
            DL_ERR(" soname=%s , nbucket=%08x", lsi->name, lsi->nbucket);

        }
    }
    *pneeded = NULL;

    if (si->has_text_relocations) {
        DL_ERR("%s has text relocations. This is wasting memory and is "
                       "a security risk. Please fix.", si->name);
        if (phdr_table_unprotect_segments7_0(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't unprotect loadable segments for \"%s\": %s",
                   si->name, strerror(errno));
            return -1;
        }
    }

    if (si->plt_rel != NULL) {
        DEBUG("[ relocating %s plt ] count=%08x", si->name, si->plt_rel_count);
        if (soinfo_relocate7_0(si, si->plt_rel, si->plt_rel_count, needed) != 1) {
            DL_ERR("relocate fail");
            return -1;
        }
    }
    if (si->rel != NULL) {
        DEBUG("[ relocating %s ]", si->name);
        if (soinfo_relocate7_0(si, si->rel, si->rel_count, needed) != 1) {
            DL_ERR("relocate fail");
            return -1;
        }
    }
#ifdef ANDROID_MIPS_LINKER
    if (!mips_relocate_got4_4(si, needed)) {
        return -1;
    }
#endif

    si->flags |= FLAG_LINKED;
    DEBUG("[ finished linking %s ]", si->name);

    DL_ERR("has_text_relocations is %08x", si->has_text_relocations);
    if (si->has_text_relocations == 1) {
        /* All relocations are done, we can protect our segments back to
         * read-only. */

        if (phdr_table_protect_segments7_0(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't protect segments for \"%s\": %s",
                   si->name, strerror(errno));
            return -1;
        }
    }
    if (phdr_table_protect_gnu_relro7_0(si->phdr, si->phnum, si->load_bias) < 0) {
        DL_ERR("can't enable GNU RELRO protection for \"%s\": %s",
               si->name, strerror(errno));
        return -1;
    }
    return 1;
}

static soinfo7_0 *load_library7_0(const char *name) {
    int fd = open_library(name);
    soinfo7_0 *soinfo = ReadElfHeader7_0(fd, name);
    return soinfo;
}

int pid = 0;

static void call_constructors_array7_0(unsigned *ctor, int count, int reverse) {
    int n, inc = 1;

    if (reverse) {
        ctor += (count - 1);
        inc = -1;
    }

    for (n = count; n > 0; n--) {
        DL_ERR("[ %5d Looking at %s *0x%08x == 0x%08x ]\n", pid,
               reverse ? "dtor" : "ctor",
               (unsigned) ctor, (unsigned) *ctor);
        void (*func)() = (void (*)()) *ctor;
        ctor += inc;
        if (((int) func == 0) || ((int) func == -1)) continue;
        DL_ERR("[ %5d Calling func @ 0x%08x ]\n", pid, (unsigned) func);
        func();
        DL_ERR(" func %s", strerror(errno));
    }
}

void init_constructors7_0(soinfo7_0 *si) {
    if (si->constructors_called)
        return;
    DL_ERR("init");
    si->constructors_called = 1;

    if (si->flags & FLAG_EXE) {
        DL_ERR("[ Calling preinit_array @ 0x%08x [%d] for '%s' ]\n", (unsigned) si->preinit_array,
               si->preinit_array_count,
               si->name);
        call_constructors_array7_0(si->preinit_array, si->preinit_array_count, 0);
        DL_ERR("[ -------%5d Done calling preinit_array for '%s' ]\n", pid, si->name);
    } else {
        if (si->preinit_array) {
            DL_ERR("--------%5d Shared library '%s' has a preinit_array table @ 0x%08x."
                           " This is INVALID.", pid, si->name,
                   (unsigned) si->preinit_array);
        }
    }

    if (si->init_func) {
        DL_ERR("[--------%5d Calling init_func @ 0x%08x for '%s' ]\n", pid,
               (unsigned) si->init_func, si->name);
        si->init_func();
        DL_ERR("[ --------%5d Done calling init_func for '%s' ]\n", pid, si->name);
    }

    if (si->init_array) {
        DL_ERR("[ -------%5d Calling init_array @ 0x%08x [%d] for '%s' ]\n", pid,
               (unsigned) si->init_array, si->init_array_count, si->name);
        call_constructors_array7_0(si->init_array, si->init_array_count, 0);
        DL_ERR("[ --------%5d Done calling init_array for '%s' ]\n", pid, si->name);
    }

}

soinfo7_0 *find_library_internal7_0(const char *name) {
    soinfo7_0 *soinfo7_0 = load_library7_0(name);
    if (soinfo7_0 == NULL) {
        return NULL;
    }
    DL_ERR("[ init_library base=0x%08x sz=0x%08x name='%s' ]", soinfo7_0->base, soinfo7_0->size,
           soinfo7_0->name);
    if (soinfo_link_image7_0(soinfo7_0) != 1) {
        munmap((void *) (soinfo7_0->base), soinfo7_0->size);
        free_info7_0(soinfo7_0);
        return NULL;
    }
    if (soinfo7_0 != NULL) {
        init_constructors7_0(soinfo7_0);
    }
    DL_ERR("LINK IMAGE SUCCESS");
    return soinfo7_0;
}

#define likely7_0(expr)   __builtin_expect (expr, 1)
#define unlikely7_0(expr) __builtin_expect (expr, 0)

void *lookup_in_library7_0(soinfo7_0 *si, const char *name) {
    soinfo7_0 *found;
    Elf32_Sym *sym;
    unsigned bind;
    found = si;
    sym = soinfo_elf_lookup7_0(si, elfhash7_0(name), name);
    if (likely7_0(sym != 0)) {
        bind = ELF32_ST_BIND(sym->st_info);
        if (likely7_0((bind == STB_GLOBAL) && (sym->st_shndx != 0))) {
            unsigned ret = sym->st_value + found->base;
            return (void *) ret;
        }
    }
    return NULL;
}