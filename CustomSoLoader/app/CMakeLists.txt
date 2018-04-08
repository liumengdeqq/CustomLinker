cmake_minimum_required(VERSION 3.4.1)

#C 的编译选项是 CMAKE_C_FLAGS
# 指定编译参数，可选
SET(CMAKE_CXX_FLAGS "-Wno-error=format-security -Wno-error=pointer-sign")

#设置生成的so动态库最后输出的路径
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../jniLibs/)

add_library( # Sets the name of the library.
             native-lib
             SHARED
             src/main/cpp/linker7_0.c
             src/main/cpp/linker4_4.c
             src/main/cpp/XorUtils.c
             src/main/cpp/native-lib.c )


target_link_libraries(native-lib
                      log
                       z
                       m)