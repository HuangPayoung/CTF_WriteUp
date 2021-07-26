64位下格式化字符串漏洞，开启NX和canary保护机制。

攻击思路：
1. 利用got表泄露libc基址。
2. 把printf函数got表改成system函数。
