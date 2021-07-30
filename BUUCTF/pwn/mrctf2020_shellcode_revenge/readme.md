64位下elf文件，跟前一道mrctf2020_shellcode类似，也是写shellcode然后跳转执行，但是多了一个检查步骤，要求每个字符在0x30-0x5a或者0x60-0x7a之间，所以要把shellcode编码成可见字符。

[参考博客](https://blog.csdn.net/weixin_44145820/article/details/105565953)
