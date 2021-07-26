64位下栈溢出漏洞，开启沙箱仅能使用`open, read, write, exit`四种系统调用。

利用栈溢出控制程序执行流，写shellcode到mmap段上再跳转过去执行。
