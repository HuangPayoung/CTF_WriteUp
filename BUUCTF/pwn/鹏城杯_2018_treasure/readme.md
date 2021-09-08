64位程序，仅开启NX保护。

# 攻击思路
可以写9字节的shellcode，利用shellcode往栈上布置rop链劫持程序流，先泄露libc基址，在拿shell。

# 参考链接
[参考博客](https://www.cnblogs.com/Rookle/p/12900913.html)
