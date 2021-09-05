国际赛果然很难，日常自闭。5道pwn搞了最容易的1道，还有1道简单的队友做出来了，剩下3道太难了到最后都没人做出了，~~就没看了~~。

## ccanary
结构体放了个指针，要溢出后面的字段就必须覆盖到指针，开了PIE不知道地址，所以写个vsyscall。

## jumpy
写shellcode，限定只能用3种op：`ret; mov eax, imm32; jmp imm8;`，而且会检查每条jmp指令目的地址的op是否合法。

用一个小技巧来绕过检查，每次写shellcode的流程：`jmp 1; mov eax, num1; mov num2;`，其中 asm(num1) = jmp 0x5，num2就是shellcode，每次只能执行4字节。

长度非常有限，所以多用push pop来给寄存器赋值，然后使用系统调用mprotect开启0x1337000000段的写权限（原先只有读和执行），再调用read往该段上写shellcode劫持程序流。
