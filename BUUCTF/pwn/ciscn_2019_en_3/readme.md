64位下elf文件，保护机制全开，只有增删两种功能，漏洞点在于删除后没有清空指针会导致UAF漏洞。

攻击思路：
1. 利用name字符串泄露elf基址，libc基址，栈地址，注意此处开了fortify保护机制，不能使用%n$p这种格式指定第几个参数，只能依次泄露。
2. tcache dup攻击，伪造fake_chunk指向栈上返回地址处，写上one_gadget并调整栈上布局（也可以用ROP调用system函数执行/bin/sh）。
