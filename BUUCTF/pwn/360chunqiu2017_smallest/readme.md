64位静态链接的程序，只有几行汇编指令。

# 攻击思路
1. 利用read系统调用返回值保存在rax寄存器，写1字节使得rax为1，就能使用write系统调用，泄露栈地址。
2. 在栈上布置srop栈帧，利用read设置rax为15进行srop，劫持rsp到泄露的栈地址。
3. 继续进行srop，往栈上写/bin/sh字符串，然后调用syscve系统调用获取shell。