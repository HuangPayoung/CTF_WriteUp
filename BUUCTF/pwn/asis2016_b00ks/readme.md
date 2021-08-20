64位堆题，保护机制全开。增删查改四项功能，漏洞点在于修改name时存在一个off-by-null漏洞。

# 数据结构
```C
struct book{
    int id;
    char *name;
    char *description;
    int size;
}
```

# 攻击思路
1. 输入name长度为0x20，使得其末尾的\x00字节被覆盖，用来泄露堆地址。
2. 修改name长度为0x20，以覆盖book1的控制结构，使其指向book1.description，提前在book1.description伪造book1结构，两个指针指向book2。
3. book2.name大小设为0x200000，保证以mmap分配，用来泄露libc基址。然后利用book1.description修改book2.description为__free_hook，再用book2写入system函数。
4. 释放一个/bin/sh堆块。
