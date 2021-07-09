输入shellcode执行，开启了沙箱进行保护，用seccomp可以看到沙箱的具体保护，白名单模式，仅允许open, read, write等几个系统调用。

shellcode执行流程：

1、在栈上写文件名称'flag\x00'，然后调用open打开flag文件。

2、在缓冲区定在栈上，调用read把flag文件中的字符串读到栈上。

3、调用write将栈上的flag输出到标准输出。
