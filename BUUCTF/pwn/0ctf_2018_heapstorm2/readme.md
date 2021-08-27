64位堆题，保护机制全开，glibc版本为2.23。增删查改四项功能，漏洞点在于修改时有一个off-by-null漏洞。

# 数据结构
```C=
struct Heap{
    __int64 xor_ptr;
    __int64 xor_size;
}
struct Heap_array{
    __int64 random_numbers[4];
    Heap heap_list[16];
}
```

# 程序分析
1. 初始化，mmap0x1000大小的空间，位于0x13370000，其中0x13370800作为程序使用的区域。调用mallopt函数把fastbins关了。读3个__int64随机数，然后给第4个随机数和后面的16个Heap结构赋值初始化。
在IDA添加一个段会比较好看，并在0x13370800处添加一个Heap_array结构体。
2. 添加功能，以Heap_list数组的size作为判断依据，找到第一个可用的结果，然后用户指定size调用calloc函数进行申请。
3. 修改功能，最多输入申请时size-12大小的内容，然后调用strcpy函数拷贝一个12字节的字符串补充至末尾，此处存在一个off-by-off漏洞。
4. 删除功能，指定index释放对应堆块，利用随机数清空对应的Heap_list结构，无UAF。
5. 展示功能，指定index打印对应堆块的内容，要求满足`Heap_array.random_numbers[2] ^ Heap_array.random_numbers[3] == 0x13377331`才可使用。

# 攻击思路
1. 利用off-by-null构造堆叠，重复布置两个，注意要在真实chunk里面伪造一个prev_size（本程序中为0x500）以绕过检查。
2. 释放chunk1（0x4e1）进large_bin，释放chunk2（0x4f1）进unsorted_bin。
3. 利用堆叠，修改`chunk2->bk=fake_chunk`，修改`chunk1->bk=fake_chunk+8`（保证chunk1->bk->fd为可写地址即可），修改`chunk1->bk_nextsize=fake_chunk-0x18-5`。
4. 申请0x50大小的堆以获取fake_chunk，会先将chunk2整理进chunk1同一个large_bin。
    * 往（fake_chunk-0x18-5）->fd_nextsize写chunk2地址，使得fake_chunk->size被赋值为0x56（也可能为0x55需要爆破）；
    * 往（chunk1->bk）->fd写unsorted_bin地址（这个和攻击无关，只是unsorted_bin归类的必走流程）；

5. 处理完chunk2后，由于伪造了chunk2->bk，下一个取的就是fake_chunk，发现刚好和申请大小相关，直接取出来满足申请。
6. 利用fake_chunk改掉4个随机数，同时利用heap_list泄露libc基址，最后完成攻击。

# 参考链接
[参考博客](https://bbs.pediy.com/thread-225973.htm#msg_header_h3_6)
