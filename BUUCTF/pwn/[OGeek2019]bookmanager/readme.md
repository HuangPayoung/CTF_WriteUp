64位堆题，保护机制全开，增删查改功能都有。主要难点应该是逆向，有各种数据结构，漏洞非常多，有off-by-one，UAF，堆溢出，我用的是堆溢出。

攻击思路：
1. 利用程序输出泄露heap基址。
2. 只有text这种结构能任意控制长度，构造一个0xb0大小的text释放后放入unsorted_bin当中，再次取出后会在bk位置存留unsorted_bin地址，用来泄露libc基址。
3. 利用堆溢出篡改section结构中保留的text指针，改为__free_hook，然后往该text写入system函数。
4. 释放一个/bin/sh堆块。
