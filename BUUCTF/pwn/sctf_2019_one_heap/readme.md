64位堆题，保护机制全开。只有增删两种功能，在添加的时候能够编辑申请到的堆块，没有展示功能，所以考虑_IO_FILE结构来泄露地址。

# 程序分析
1. 添加功能，总共保存一个指针，用户指定size范围为[0, 0x7f]，也就是只能申请0x20-0x90范围内的堆，然后往申请的堆读入指定的size字节。
2. 删除功能，释放保存的指针，没有清空指针导致UAF漏洞。

# 攻击思路
1. 申请chunk0，double_free造成`chunk0->fd=chunk0`，修改末2字节使fd指向tcache_perthread_struct，这里需要爆破高字节的高4位，有1/16的成功概率。
2. 申请同样大小拿出chunk0，再次申请拿出tcache_perthread_struct，申请出来之后修改tcache_perthread_struct.count[0x23]=0x7，使得tcache中的0x250堆块满了，
再把tcache_perthread_struct释放进unsorted_bin。
3. 切割放入unsorted_bin当中的tcache_perthread_struct，申请的时候合理布置count数组中各个项的值以保证每次都从tcache_perthread_struct。
4. 通过切割把unsorted_bin的地址写到tcache_perthread_struct.entry[2]的位置。再申请一个0x20大小的堆进行partial_write，改低2字节使其指向_IO_2_1_stdout_，这里也需要爆破高字节的高4位。
5. 申请0x40大小的堆拿到_IO_2_1_stdout_，改_flag=0xfbad1800，partial_write改_IO_write_base最低字节位0x58，这个地址是_IO_2_1_stderr_->vtable=_IO_file_jumps，可以用来泄露libc基址。
6. 泄露libc基址后，继续切放在unsorted_bin当中的tcache_perthread_struct，用同样的技巧往tcache_perthread_struct.entry[6]写入__free_hook-8。
7. 申请0x80大小的堆，会去tcache中0x80的链表拿我们伪造的fake_chunk，然后往__free_hook-8写入b'/bin/sh\x00'，往__free_hook写入system函数，最后释放该fake_chunk。

# 参考链接
[参考博客](https://www.it610.com/article/1290998882838323200.htm)
[参考博客](https://www.cnblogs.com/LynneHuan/p/14730087.html)
