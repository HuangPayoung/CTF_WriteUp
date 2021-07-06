栈溢出，构造ROP完成攻击。

第一次ROP链，调用write函数泄露read函数got表地址，以获取libc基址，然后返回main函数。

第二次ROP链，调用system函数执行/bin/sh。
