32位下栈溢出，没有开启任何保护机制。

按照程序的逻辑，泄露的栈地址，应该是能够在栈上写shenllcode然后直接跳转过去的，本地按照这个思路也能打通。

比较坑的地方是程序没有关掉输出的缓冲区，这就导致在打远程的时候泄露的栈地址根本不会回显，远程也就打不通了。

网上有别的思路，构造两次ROP链完成攻击也是可行的。

我采用的思路是，用ROP链控制执行流程，先调用read函数把shellcode写到bss段上一个可执行的区域，然后再跳转过去。