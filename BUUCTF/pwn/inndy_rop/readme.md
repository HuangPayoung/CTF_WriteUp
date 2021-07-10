32位下栈溢出，静态编译的elf文件，先调用read写/bin/sh字符串到bss段上，在用系统调用execve执行。
