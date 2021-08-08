64位elf文件，保护机制全开，glibc版本为2.27有tcache，漏洞在于更新处有一个off-by-null漏洞。

程序分析：
1. 初始化mmap随机申请一块0x1000空间并打印出地址，权限为7（RWX），可以写shellcode然后跳转执行。
2. 添加功能，指定长度小于0x1000即可，申请完会打印出存放该指针的地址，注意是存放指针的地址，而不是指针保存的那个malloc返回地址。
3. 删除功能，情况指针数组和长度数组对应项，无UAF漏洞。
4. 修改功能，可输入最初申请的长度，存在一个off-by-null漏洞。

攻击思路：
1. 先保存mmap申请的地址，另外利用添加时打印的地址，可以泄露elf加载基址。
2. 有elf基址后就可以知道对应指针数组的地址，unlink攻击修改该数组，往mmap段写入shellcode。
3. 利用off-by-null构造堆叠，chunk1（0x420）放入unsorted_bin，chunk2（0x20）为被叠的堆块，chunk3（0x500），利用chunk2覆盖chunk3的prev_size和size域最低1字节。
释放chunk3就会往前将chunk1，chunk2一同合并放入unsorted_bin，但是此时chunk2的指针还保存在数组中。
4. 依次重新申请0x420和0x20的堆，先将之前未释放的chunk2放入tcache，然后利用相似的过程造成堆叠，往chunk2的fd域写unsorted_bin地址，然后利用partial write把最低字节改成\x30，
tcache（0x20）单向链表中就会有__malloc_hook，申请出来写入mmap段地址，再次malloc就会触发__malloc_hook然后跳转mmap段执行shellcode。

踩坑点：
前两步完成后，虽然写好shellcode，但是不知道怎么劫持程序流到mmap段。开了RELRO没法改got表，不能泄露libc基址改__malloc_hook和__free_hook，也不知道栈地址没法覆盖返回地址。
然后到网上看其他师傅的做法，用了非常巧妙的堆布局来利用off-by-null漏洞，造成了堆叠。另外我看到有师傅直接在unlink后bss段上的指针列表那个区域伪造fake_chunk（0x90），然后放入unsorted_bin。
在2.23版本下还没有tcache这么做也可以，但是2.27后有了tcache要放入unsorted_bin要么把0x90的tcache先填满，要么用0x420以上的堆，这两种做法在bss段上那里都不太好实现，所以参考了另外一位师傅堆叠的做法。

[参考博客](https://eqqie.cn/index.php/laji_note/1077/) [参考博客](https://www.cnblogs.com/lemon629/p/13842163.html)
