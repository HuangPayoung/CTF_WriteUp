栈溢出，没有方便用的函数，只能ROP调用系统调用来实现。

学习了SROP的机制，之前看过这个攻击但是没认真学，网上看别人的wp重新认真学一遍。

具体原理是，切换到内核态时要将各寄存器以一个帧（Frame）的形式保存在栈上，以便后续恢复现场，所以攻击方式就是在栈上布置好这个帧，然后调用sigreturn，方式和其他系统调用类似，将RAX赋值为15然后调用syscall指令。

解题步骤：

1.第一次溢出先泄露栈地址，以便后续在栈上写字符串利用，然后返回main函数。

2.第二次溢出就构造SROP，程序中有将RAX赋值为15和59的gadget，分别可以用来执行sigreturn和sys_execve，此处使用SROP，然后使用pwntools提供的工具布置Frame，给RAX, RDI, RSI, RDX, RIP等寄存器赋好值。

3.以系统调用的形式执行sys_execve('/bin/sh\x00', 0, 0)，其中 RAX = 59, RDI = bin_sh_addr, RSI = 0, RDX = 0, RIP = syscall。

ps：网上其他师傅还有别的解法，64位下通过ret2csu的通用gadget片段也能够给RDI, RSI, RDX这几个寄存器赋好值，RAX调用程序中的gadget，RIP通过ROP链控制，也是能够实现攻击的，此处偷懒省略...
