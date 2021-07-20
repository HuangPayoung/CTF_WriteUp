32位下elf文件，格式化字符串漏洞，仅开启NX保护机制。

攻击思路：
1. 查看.finiarray可以发现有一个函数地址，所以第一次格式化字符串先篡改该地址，劫持程序流能返回到main函数再次攻击，顺便在第一次格式化字符串中把printf函数got表改为system函数plt表。
2. 第二次进入main函数，输入/bin/sh字符串，此时printf函数已被改成system函数，即可获取shell。
