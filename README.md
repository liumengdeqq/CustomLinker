
1.实现动态load so 实现data段进行加密 


2.实现工具是android studio3.0以上 和ndk16版本以上

3.libfoo.so是没有加密的so libdata.so是加固之后的so


难点分析
   1.在android 7.0之后dlopen不返回soinfo结构体，通过读取maps 获取基地址读取系统so的结构体
   
   2.在android5.1之后 出现read被pread64函数读取so的结构
       
   3.在android4.1.2 5.0 7.0等page_size 也是内存大小有改变
     
   4.在android4.4之后都是c++ 考虑安全问题 用c语言实现


参考TK大神

https://bbs.pediy.com/thread-216119.htm

https://bbs.pediy.com/thread-191649.htm

https://bbs.pediy.com/thread-197512.htm
