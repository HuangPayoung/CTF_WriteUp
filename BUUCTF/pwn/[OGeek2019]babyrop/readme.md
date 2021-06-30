32位下的ROP，生成随机数并与用户输入的数字进行比较来检查，绕过方法用/x00，strlen函数存在0截断。

第一次ROP链调用puts_plt泄露出puts_got地址，获取libc基址，并重新回到main函数。

第二次ROP链调用system函数执行/bin/sh\x00。
