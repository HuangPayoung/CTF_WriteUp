32位elf文件，静态链接，看起来像直接用汇编写成的程序。栈溢出漏洞，gadget片段非常少。

# 攻击思路
1. alarm()函数的妙用，第一次调用alarm(10)之后，如果第二次调用alarm(N)参数随意，就会返回前一次调用alarm()到现在剩下的时间，这个参数保存在eax。
2. 由于程序中的gadget片段非常少，难以直接得到shell，考虑open-read-write来泄露flag，其中read，write函数在程序中已经实现了，通过第一步中的思路把eax控制为5就可以调用open函数。
3. 注意，本题文件中的栈只使用了esp寄存器，传参和读参都通过esp的相对偏移来设置，利用程序中的gadget片段，可以用栈上的值给ebx，ecx，edx赋值，然后利用alarm()函数的技巧来控制eax为5，打开/flag文件。
4. 接下来就调用read，write函数来泄露flag。

# 踩坑
一开始不知道alarm函数的技巧，一直想的是利用read函数的返回值会保存在eax寄存器，然后根据这个来控制程序。但是做到后面发现溢出长度不够，只能控制到ebx和ecx寄存器，edx寄存器没法控制，
就没法成功调用execve系统调用了。

# 参考链接
[参考博客](https://blog.csdn.net/seaaseesa/article/details/105587858)
