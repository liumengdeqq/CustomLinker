//
//  main.c
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/1/30.
//  Copyright © 2018年 com.qunar. All rights reserved.
//

//#include <stdio.h>
//#include "Utils.h"
#include "Encryption.h"
//char *white[]={"/system/lib/libc.so","/system/lib/liblog.so","/system/lib/libm.so","/system/lib/libdl.so","/system/lib/libstdc++.so"};
//int iswhite(char* name){
//    for(int i=0;i<strlen(white);i++){
//        if(strcmp(name, white[i])==0){
//            return 1;
//        }
//    }
//    return 0;
//}
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define PAGE_MASK (~(PAGE_SIZE-1))
// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#define BIONIC_ALIGN(value, alignment) \
(((value) + (alignment) - 1) & ~((alignment) - 1))
#define UINT32_MAX       (4294967295U)
#  define dddd_MAX    INT32_MAX
int main(int argc, const char * argv[]) {
    // insert code here...
//    printf("Hello, World!\n");
//    printf("%0x",(0xffffffba));
//    size_t rounded = BIONIC_ALIGN(4294967296, PAGE_SIZE);
//    if (rounded < 4097 || rounded > dddd_MAX) {
//        printf("ddddd");
//    }
//    printf("%ul\n",PAGE_SIZE);
    encryption("/Users/liumeng/shell/shell/shell/libdata.so");
    
//    pid_t pid=getpid();
//    MemoryMap myMap;
//    char *name="/system/lib/libc.so";
//    if(iswhite(name)==1){
//         hookSoAddress(pid,myMap,name);
//    }

    return 0;
}
