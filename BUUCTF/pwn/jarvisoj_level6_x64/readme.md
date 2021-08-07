64位下elf文件，开启NX和canary保护机制，增删查改四项功能，漏洞点在于删除时没有清空指针，导致UAF漏洞。

攻击思路：
1. 先放两个small_chunk进unsorted_bin当中，利用双向链表中的bk指针来泄露heap基址以及libc基址。
2. 利用edit功能realloc函数扩展堆块，虽然是正常申请堆块没有溢出，但是由于没有清空指针，就可以构造堆布局然后double free野指针来实现unlink攻击。
3. 修改got表函数，获取shell。

[参考博客](https://blog.csdn.net/weixin_45427676/article/details/105495608)
