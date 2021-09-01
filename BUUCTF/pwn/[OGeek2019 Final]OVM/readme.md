第一次做虚拟机pwn。其实不是真正的虚拟机，只是软件层面模拟CPU提供了一些指令。做题要找指令集当中的漏洞来实现逃逸，控制真正的内存来实现pwn。

# 程序分析
1. 程序模拟一个32位的CPU，提供0x10000 * 4的内存，16个4字节的栈空间（没啥用），16个4字节的寄存器，其中reg[13]表示SP寄存器，reg[15]表示PC寄存器。
2. 用户指定指令长度，然后往内存中写指令，以running变量为标志表示VM正在执行当中，调用fetch函数取指，调用execute函数执行指令。
3. 根据execute函数，整理出程序实现了以下指令集，漏洞点在于load和store功能，在memory和reg间传输数据，没有检测memory下标，从而可以控制任意地址写。

```
instruction = (op << 24) + (num1 << 16) + (num2 << 8) + num3
SP: reg[13] PC: reg[15]
op = 0x10 reg[num1] = num3            
op = 0x20 reg[num1] = (num3 == 0)
op = 0x30 reg[num1] = memory[reg[num3]]
op = 0x40 memory[reg[num3]] = reg[num1]
op = 0x50 stack[SP++] = reg[num1];
op = 0x60 reg[num1] = stack[--SP]
op = 0x70 reg[num1] = reg[num2] + reg[num3]
op = 0x80 reg[num1] = reg[num2] - reg[num3]
op = 0x90 reg[num1] = reg[num2] & reg[num3]
op = 0xa0 reg[num1] = reg[num2] | reg[num3]
op = 0xb0 reg[num1] = reg[num2] ^ reg[num3]
op = 0xc0 reg[num1] = reg[num2] << reg[num3]
op = 0xd0 reg[num1] = reg[num2] >> reg[num3]
op = 0xe0 if sp == 0: halt; else: jump 0xff
op = 0xff print reg[0:16] halt;
op = (0xd0, 0xe0) | (0xe0, 0xff) nop
```

# 攻击思路
1. 利用memory下标越界，先将data段上got表加载至reg当中，尽量挑选接近__free_hook的地址，因为VM是32位所以要分两步实现。
2. 补上差值，将reg中的值改为`__free_hook - 8`，然后把该地址写到comment变量中。退出VM，利用打印reg功能泄露libc基址。
3. 往伪造的comment变量写`/bin/sh`并将system函数写入__free_hook，从而实现攻击。

# 参考链接
[参考博客](https://www.cnblogs.com/lemon629/p/13975686.html)

[参考博客](https://blog.csdn.net/seaaseesa/article/details/105862737)
