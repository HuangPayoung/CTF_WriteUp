64位下堆题，有增删查三大功能，漏洞点在于删除处，没有清空指针，会导致UAF漏洞。

程序分析：

用来保存信息的控制结构，0x18大小，申请到0x20大小的堆。
```C
struct info{
    char *name;
    int name_size;
    char call[12];
}
```

攻击思路：
1. 申请足够大不被放入tcache的堆，释放放入unsorted_bin当中，然后利用UAF漏洞泄露libc基址。
2. glibc2.27下没有检查tcache的double-free，在tcache单向链表中伪造在___realloc_hook的fake_chunk，最终分配到fake_chunk，在__realloc_hook写one_gadget，在__malloc_hook写realloc的一个偏移指令以调整栈上的布局。
