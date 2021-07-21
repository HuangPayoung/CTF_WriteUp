32位下栈溢出程序，没有开启任何保护机制，可以在栈上写shellcode然后跳转执行。

攻击思路：在栈上布置shellcode，根据提示hint可以把eip控制为esp处，所以使用该指令劫持程序流到栈上，然后布置一个小片段`sub esp, 0x28; jmp esp;`利用偏移跳转到shellcode处。
