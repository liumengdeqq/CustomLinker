//
//  exec.h
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/1/30.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

#ifndef _ARM_EXEC_H_
#define _ARM_EXEC_H_

#define __LDPGSZ    4096

#define NATIVE_EXEC_ELF

#define ARCH_ELFSIZE        32

#define ELF_TARG_CLASS        ELFCLASS32
#define ELF_TARG_DATA        ELFDATA2LSB
#define ELF_TARG_MACH        EM_ARM

#define _NLIST_DO_AOUT
#define _NLIST_DO_ELF

#define _KERN_DO_AOUT
#define _KERN_DO_ELF

#endif  /* _ARM_EXEC_H_ */
