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
int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Hello, World!\n");
    encryption("/Users/liumeng/shell/shell/shell/libfoo.so");
//    pid_t pid=getpid();
//    MemoryMap myMap;
//    char *name="/system/lib/libc.so";
//    if(iswhite(name)==1){
//         hookSoAddress(pid,myMap,name);
//    }

    return 0;
}
