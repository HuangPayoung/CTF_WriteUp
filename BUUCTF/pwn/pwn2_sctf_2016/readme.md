逻辑漏洞，没有正确处理有符号数与无符号数，导致栈溢出。

第一次溢出，ROP链调用printf函数，由于没有好的输出函数，可以使用包含%s的格式化字符串来泄露地址信息，此处用printf_got，以获取libc基址，然后返回main函数。

第二次溢出，ROP链调用system函数，执行/bin/sh。