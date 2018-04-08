#include <sys/types.h>
#include <fcntl.h>

#include "Utils.h"

#define MAX_SEGMENT_INTERVAL 10 * 4096  // 10 pages
#ifdef __LP64__
#define MAX_COUNT 2048
#else
#define MAX_COUNT 1024
#endif
int loadMemoryMap(pid_t pid,MemoryMap *map) {
#ifdef __LP64__
    char raw[64000];
#else
    char raw[8000];
#endif
    
    char name[MAX_NAME_LENGTH];
    char *p;
    unsigned long start, end;
    int itemCount = 0, fd, returnValue;
    
    //    sprintf(raw, "/proc/%d/maps", pid);
    fd = open("/Users/liumeng/Desktop/maps", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    memset(raw, 0, sizeof(raw));
    p = raw;
    
    while(1) {
        returnValue =(int)read(fd, p, sizeof(raw) - (p - raw));
        if (returnValue < 0) {
            
            return -1;
        }
        if (returnValue == 0) {
            break;
        }
        p += returnValue;
        if (p > raw + sizeof(raw)) {
            
            return -1;
        }
    }
    close(fd);
    p = strtok(raw, "\n");
    while (p) {
        if(itemCount<1024){
#ifdef __LP64__
            returnValue = sscanf(p, "%012lx-%012lx %*s %*s %*s %*s %s\n", &start, &end, name);
#else
            returnValue = sscanf(p, "%08lx-%08lx %*s %*s %*s %*s %s\n", &start, &end, name);
#endif
            p = strtok(NULL, "\n");
            if (returnValue == 2) {
                map[itemCount].start=start;
                map[itemCount].end=end;
                strcpy(map[itemCount].name, name);
                continue;
            }
            map[itemCount].start=start;
            map[itemCount].end=end;
            strcpy(map[itemCount].name, name);
            itemCount++;
        }
    }
    
    return 0;
}

int hookSoAddress(pid_t pid,MemoryMap myMap,char *soLibName){
    MemoryMap map[MAX_COUNT];
    int count;
    int ret = 0;
    for(count=0;count<MAX_COUNT;count++){
        map[count].end=0;
        map[count].start=0;
    }
    ret = loadMemoryMap(pid,map);
    if (ret < 0) {
        return -1;
    }
    char *libName = NULL;
//    char *libcName="/system/lib/libc.so";
    unsigned long start=0;
    unsigned long end=0;
    int isHas=0;
    for (int i = 0; i < MAX_COUNT; i++) {
        libName = map[i].name;
        if(strcmp(libName,soLibName)==0){
            isHas=1;
            if(start>map[i].start||start==0){
                start=map[i].start;
            }
            if(end<map[i].end|| end==0){
                end=map[i].end;
            }
        }
    }
    if(isHas==0){
        return -1;
    }else if(isHas==1){
        myMap.start=start;
        myMap.end=end;
        printf("libName=%s\n,start---%lx,end---%lx\n",soLibName,start,end);
    }
  
    return 0;
}

