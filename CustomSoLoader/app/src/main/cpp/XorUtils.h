//
//  XorUtils.h
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/2/6.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

#ifndef XorUtils_h
#define XorUtils_h
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "elf.h"
#include <sys/mman.h>
#define DEBUG

typedef struct _funcInfo{
  Elf32_Addr st_value;
  Elf32_Word st_size;
}funcInfo;
int xor_code(Elf32_Addr baseParam,void* start_page_address,Elf32_Addr start_page_filelength);

#endif /* XorUtils_h */
