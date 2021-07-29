64位下堆题，增删查三项功能，保护机制全开，添加新堆时有一个off-by-null漏洞。

程序分析：
1. 添加功能，能申请0-0x2000大小的堆，首先将内容读到栈上缓冲区，然后再调用strcpy函数拷贝到堆上，会溢出一个null字节。
2. 打印功能，打印堆指针的内容，puts函数会存在0截断。
3. 删除功能，将堆空间的内容置为0xDA后再free掉，且清空指针列表和size列表对应项。

攻击思路：
1. 构造堆布局，chunk0，chunk1，chunk2，其中chunk0和chunk2都必须大于tcache范围。释放chunk0和chunk1，重复利用添加chunk1时的off-by-null漏洞依次清空chunk2->size->prev_inuse和chunk2->prev_size。
清空prev_inuse是为了释放chunk2的时候和前面两堆块合并造成堆叠，清空prev_size是因为合并时根据prev_size大小进行合并，而我们要伪造prev_size，高字节为0会导致零截断而使得prev_size的高字节没法控制。 
2. 添加chunk1并伪造chunk2->prev_size = chunk0->size + chunk1->size，释放chunk2时会根据chunk2->prev_size将chunk0，chunk1，chunk2一起合并放入unsorted_bin，而此时还有一个chunk1指针在外面可以控制。
3. 申请一个chunk0大小的堆，unsorted_bin地址则放入chunk1中，用来泄露libc基址。
4. 再此申请chunk1，此时有两个指针指向chunk1，使用tcache_dup攻击来伪造一个指向__malloc_hook处的fake_chunk，然后写入one_gadget。

踩坑点：
1. 一开始构造堆布局的时候，chunk0和chunk2随意指定大小，以至于合并的时候没法通过检查，因为chunk2->prev_size != chunk0->size，显示报错```corrupted size vs. prev_size```。
后面指定chunk0和chunk2大于tcache范围，直接放入unsorted_bin就可以避免这个检查。
2. 最后pwn的时候想在__free_hook处写上system函数，然后释放一个/bin/sh堆块，但是这题删除的时候会把堆中内容置为0xDA，所以这种攻击就没法奏效了，只能在__malloc_hook处写one_gadget。

[参考博客](https://blog.csdn.net/weixin_44145820/article/details/105433911) [参考博客](https://www.cnblogs.com/luoleqi/p/13514092.html)
