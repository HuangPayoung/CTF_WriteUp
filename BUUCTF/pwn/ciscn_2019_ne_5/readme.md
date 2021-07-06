栈溢出，Add功能中添加log，然后GetFlag函数当中把log拷贝到栈上再打印出来，此处发生溢出。

ROP链调用system函数，没有合适的/bin/sh\x00字符串，可以调用其他函数打印到bss段上，这里用了fflush字符串的末两位sh也能成功。
