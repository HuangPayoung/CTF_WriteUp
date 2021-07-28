64位下堆题，增删改三项功能，开启NX和canary保护机制，漏洞点在于读取内容，如果长度设置为0会导致整数溢出从而堆溢出。

攻击思路：没开PIE，用unlink攻击。

[参考博客](https://www.wangan.com/docs/1956)
