64位elf文件，保护机制全开。

# 程序分析
初始化打印出了puts地址，可以泄露libc基址，然后输入一个long int数字，可以修改该数字的地址开始处3字节，3字节也由用户指定。
有一个检查，似乎是针对one_gadget的检查，但是除了第三个没啥用，ASLR机制会导致第二字节的高4位随机，所以检查都能通过。

# 攻击思路
尽管elf文件开了RELRO保护，不能改它的got表，但是在libc中的got表是可以修改的，而且程序一开始也泄露了libc基址，所以可以想办法修改libc中的got表来劫持程序流。
1. 攻击思路1，修改3字节后会调用puts函数再退出，而puts函数里面会调用strlen函数来获取字符串长度，所以可以修改strlen函数的got表。
此处踩坑，我在本地和远程都跑不通，后面用gdb一步一步跟，发现在调用puts函数之前还有一个dlopen函数，它执行会直接导致程序崩掉，执行不到下一句puts函数。
2. 攻击思路2，修改3字节后会调用dlopen函数，而且会报错，最终调用`_dl_catch_error`并退出，所以可以劫持_dl_catch_error对应的got表来控制程序流。

# 参考链接
[参考博客](https://www.cnblogs.com/countfatcode/p/13951283.html)

[参考博客](https://www.cnblogs.com/LynneHuan/p/14687617.html)

[参考博客](https://www.cnblogs.com/lemon629/p/14290240.html)
