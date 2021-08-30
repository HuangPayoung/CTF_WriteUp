32位静态编译的elf文件，仅开启了NX保护，栈溢出漏洞。

# 攻击思路
1. 根据用户输入内容进行base64解码，但是解码后最长只能为12字节。
2. 在auth函数中只能覆盖到ebp变量，退出auth函数时，将ebp覆盖成input地址。
3. 在main函数中，由于控制了ebp，退出时执行`leave; ret;`指令就会将栈劫持到input处，从而执行后门。

# 参考链接
[参考博客](https://blog.csdn.net/wxh0000mm/article/details/91040164)
