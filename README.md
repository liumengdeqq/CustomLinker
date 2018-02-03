# CustomLinker
1.去掉dlopen加载 android在7.0之后dlopen不返回 soinfo 使用 本身的find_library

2.现在实现32位

3.在获取so的根内存地址时候用本身进程中的maps文件中的地址

4.使用的是4.1.2的android源码linker

5.使用的华为g520 4.1.2的系统测试成功

6.可以给予自定义linker进行自身加固

希望通过开源使自身代码更牢固

参考tk大神

https://github.com/liumengdeqq/CustomLinker
