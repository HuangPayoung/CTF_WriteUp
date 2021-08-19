32位elf文件，开了NX和canary保护机制，格式化字符串漏洞。

# 攻击思路
改printf函数got表位system函数plt表，然后再次跳转vuln函数输入/bin/sh\x00。一开始想着改.fini.array，后面到gdb看了一下发现不可写，所以就改puts函数got表来劫持程序流。
