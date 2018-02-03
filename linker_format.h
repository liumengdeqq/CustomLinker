//
//  linker_format.h
//  Goblin_Shell_4.1.2
//
//  Created by liu meng on 2018/1/30.
//  Copyright © 2018年 com.qunar. All rights reserved.
//
#ifndef _LINKER_FORMAT_H
#define _LINKER_FORMAT_H

#include <stdarg.h>
#include <stddef.h>

/* Formatting routines for the dynamic linker's debug traces */
/* We want to avoid dragging the whole C library fprintf()   */
/* implementation into the dynamic linker since this creates */
/* issues (it uses malloc()/free()) and increases code size  */

int format_buffer(char *buffer, size_t bufsize, const char *format, ...);

#endif /* _LINKER_FORMAT_H */
