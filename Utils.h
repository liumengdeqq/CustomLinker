//
//  Utils.h
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/2/2.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _UTILS_H_
#define _UTILS_H_

#define MAX_NAME_LENGTH 256
#define MEMORY_ONLY "[memory]"

typedef struct {
    char name[MAX_NAME_LENGTH];
    unsigned long start, end; // memory address start/end of components
} MemoryMap;
int hookSoAddress(pid_t pid,MemoryMap myMap,char* soLibName);
int loadMemoryMap(pid_t pid,MemoryMap *map);
#endif


