32位下静态编译的elf文件，栈溢出漏洞，没有system函数所以只能使用ROP拼接实现系统调用。

第一步：先调用read函数将/bin/sh字符串写到bss段上的某个缓冲区。

第二步：采用系统调用的方式调用execve函数执行/bin/sh。

踩坑点：

1、IDA静态分析得到的偏移不正确，栈上缓冲区的空间应该是0x1c，而不是反汇编里面显示的0x14。

2、一开始没用read函数写/bin/sh字符串，虽然程序当中没有这个完整的字符串，但是利用flush字符串的末尾可以得到sh字符串，在其他情况（比如system函数）下仅用sh其实就够了，能够直接获取到shell。
但是在本题当中我发现不行，仅用sh不能成功获取到shell，可能是系统调用需要一个完整的执行路径，没有环境变量，没办法直接用sh调用shell。
