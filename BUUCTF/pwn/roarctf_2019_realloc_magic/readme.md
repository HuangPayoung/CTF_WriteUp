64位堆题，glibc版本2.27，保护机制全开，功能和往常堆题有些不同，漏洞点在于删除时没有清空指针。

# 程序分析
* 添加功能，调用realloc函数进行分配，程序只保存一个指针，大小可随意指定，然后往申请的指针读入指定长度。根据其他师傅的描述介绍一下realloc函数的特性：
    
函数原型：`void *realloc(void *ptr, size_t size)`，题目的调用方式：`realloc_ptr=realloc(realloc_ptr, size)`，size由用户指定。
1. size == 0 ，等同于free。函数返回NULL，可以把全局变量`realloc_ptr`清空。
2. realloc_ptr == 0 && size > 0 ， 等同于malloc，返回`malloc(size)`申请的指针。
3. malloc_usable_size(realloc_ptr) >= size，不会对ptr进行操作，以原chunk返回给用户。所以相当于edit，但size<=chunk的最大数据空间。
4. malloc_usable_size(realloc_ptr) < szie，返回一块新size的堆空间。获取new_chunk有两种情况（本题的攻击使用第二种情况）：
    * 第一种情况，当高地址有连续的空间可以分配，例如unsorted_bin或者top_chunk，往高地址扩展直至当前chunk满足size大小。
    * 第二种情况，上述情况不符合时，先malloc(size)获取一个new_chunk，然后调用memcpy将old_chunk中内容拷贝至new_chunk，最后free(old_chunk)。

* 删除功能，调用free函数释放保存的指针，未清空指针导致UAF漏洞。
* 清空功能，菜单输入666时能够把保存的指针清零，只能调用一次，这个功能用于清空伪造的fake_chunk。因为如果使用realloc来清空realloc_ptr，`realloc_ptr = realloc(realloc_ptr, 0)`，
会先释放掉fake_chunk，但是我们构造的fake_chunk无法改到size域，没法通过free函数的检查。

# 攻击思路
1. 泄露libc基址，由于本题没有打印功能，所以利用IO_FILE结构体进行地址泄露。
    * 申请chunk0（0x20）chunk1（0x90）chunk2（0x30）。chunk2用来隔离top_chunk，保证chunk1后面能进unsorted_bin而不会和top_chunk合并。这里用到一个小技巧，申请chunk0后，
调用`realloc_ptr = realloc(realloc_ptr, 0);`，会把chunk0释放放入tcache，同时清空`realloc_ptr`指针。这样再次调用realloc申请chunk1，就能从top_chunk切下目标大小的chunk1。
如果用free释放chunk0，指针没有被清空，下次realloc会从chunk0开始往top_chunk扩展，就没法将chunk0和chunk1分开，得到独立的堆块。
    * 利用删除功能未清空函数指针，连续7次释放chunk1以填满tcache，第8次用realloc释放chunk1，将其放入unsorted_bin中并清空realloc_ptr指针，此时chunk1的fd，bk域均指向unsorted_bin。
    * 先申请0x20的堆拿回chunk0，再将chunk0扩展为0xb0，因为chunk1已经进了unsorted_bin，realloc函数就会拿chunk1来扩展chunk0，刚好满足0xb0的size要求，此时就会造成堆叠，
chunk1还在tcache（0x90）链表当中。编辑chunk0造成堆溢出，把chunk1->size改为0x41使其后续释放被放入tcache（0x40）链表避免干扰，partial write修改chunk1->fd，改低2字节为0xX760，
目标是往tcache（0x90）链表伪造_IO_2_1_stdout_这个fake_chunk，其中低12位是固定的，高4位需要爆破，有1/16的概率成功。
    * 用realloc释放fake_chunk0（0xb0）并清空指针，用realloc()申请0x90拿回chunk1并把fake_chunk移至tcache（0x90）链表头部，用realloc释放fake_chunk1（0x40）并清空指针，
用realloc()申请0x90拿到fake_chunk，就可以修改_IO_2_1_stdout_来泄露libc地址。用stdout泄露地址时，需要改_flag字段为0xfbad1800，_IO_write_base指向要泄露的地址，_IO_write_ptr指向泄露结束的地址，
前两个是必须设置的，最后一个一般不设置也可以。
    * 由于ASLR不知道此题libc的基址，所以还要采用partial write的技术来覆盖_IO_write_base，理想状态下只改最低字节，因为ASLR不会影响末12位，如果要改两字节及以上就要开始爆破了。
调试过程中发现刚好1字节就可以满足了，修改最低字节为0x58，就会使得_IO_write_base指向_IO_2_1_stderr_的vtable位置，这个vtable在libc里面是固定偏移的，所以就能泄露libc基址。
另外有一个小发现，从低地址到高地址stderr的IO_FILE结构和stdout的IO_FILE结构刚好相邻，但是stdin的IO_FILE结构没有连在一起。
2. 攻击利用：和泄露时候相同的思路，构造堆叠以修改tcache链表的fd域指向__free_hook，然后写入system函数并释放一个/bin/sh堆块，从而获取shell。

# 参考链接
[参考博客](https://blog.csdn.net/qq_41202237/article/details/113845320?spm=1001.2014.3001.5501)

[参考博客](https://blog.csdn.net/weixin_44145820/article/details/105585889)
