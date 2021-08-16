64位堆题，保护机制全开而去有沙箱，增删查改功能都有，漏洞点在于删除时没有清空指针。

# 数据结构
```C
struct Hero{
    char *name;
    __int64 size;
}
```
IDA识别有点问题，在bss段上最多可以保存3个，而不是2个。

# 程序分析
1. 添加功能，用户指定index，输入name，根据name长度用calloc申请堆块，有零截断问题，长度范围[0x80, 0x400]，把申请的指针和长度保存在bss段上的数组对应项。
2. 编辑功能，可输入数组中对应项的长度，无零截断问题。
3. 展示功能，指定index打印name指针。
4. 删除功能，指定index释放name指针，但是没有清空指针导致UAF漏洞。
5. 后门函数，调用条件是tcache.count[0x20]也就是0x220大小的堆数量大于6，用malloc申请固定长度0x217大小的堆块（0x220），然后最大读入0x217，无零截断。

# 攻击思路
1. 用0x220大小的堆填满tcache，然后继续释放一个进unsorted_bin，利用UAF漏洞泄露heap基址和libc基址。
2. 往tcache（0x90）放6个堆，然后往smallbin（0x90）大小放两个堆。这个用一个非常秀的技巧：如果直接释放0x90大小的堆因为tcache不满就会放入tcache，这样就没法实现攻击；
先申请一个大的堆然后释放放入unsorted_bin，把这个堆切剩0x90留在unsorted_bin，下次申请大于0x90的会把它整理进smallbin（0x90）当中，重复用两次得到两个small_chunk（0x90）。
3. 利用UAF修改tcache（0x220）的单向链表，写入__malloc_hook（位于链表第二个），同时写入要读的文件名'/flag'，后面方便分配出来控制程序流。
4. 利用UAF漏洞造成堆溢出：为了得到第二个small_chunk，要把一个较大的堆释放进unsorted_bin，并切割剩下0x90作为small_chunk2，保留这个大堆块的指针，它的范围能覆盖到small_chunk2，
就可以修改第二个small_chunk->bk，同时在堆上写ROP链（泄露堆地址就知道该ROP链的地址，后面再栈劫持）。
5. 用后门从tcache（0x220）取出一个堆，此时tcache->count[0x20]变为6，没法继续用后门函数，__malloc_hook位于tcache（0x220）第一个chunk。
6. 采用tcache_stashing_unlink_attack攻击：添加功能用calloc申请0x80的堆，会去smallbin（0x90）中取small_chunk1。此时tcache（0x90）数量为6，会从当前smallbin（0x90）中取出
small_chunk2以填满tcache，由于我们伪造了bk指针，这时会往bck->fd写入smallbin（0x90）的地址，我们改`small_chunk2->bk = heap_base + 0x30 - 0x10 - 5`，
这样就会往tcache.count[0x20]写入0x7f（smallbin的最高位地址），然后就可以任意调用后门函数了。
7. 往__malloc_hook写入一个`add rsp, 0x48; ret;`gadget，因为下次在添加的时候，会先把name放在栈上，算好偏移为0x48，在name写一个`pop rsp; ret;`gadget实现栈劫持，
到之前堆上布置的ROP链执行ORW。

# 踩坑点
1. 一开始使用tcache_stashing_unlink_attack攻击的时候，想的是用0x220的small_chunk来构造。因为可以填满tcache（0x220），然后放两个进smallbin，再用后门函数从tcache取出一个，
也符合tcache_stashin_unlink_attack的攻击条件。但是在实际调试的过程中发现，从smallbin取出small_chunk2放入tcache，此时确实会向伪造的small_chunk2->bk->fd写入smallbin，
能够把tcache.count[0x20]写为0x7f。但是后面还会判断tcache满不满要不要继续取下一个放入，判断方法是：程序会把之前tcache.count[0x20]的值0x6放入寄存器当中，放一个small_chunk2后，
把该寄存器+1变为0x7，发现tcache满了就不会放了，然后把寄存器的值0x7写回tcache.count[0x20]，导致我们之前的攻击被覆盖掉了，所以执行这个攻击要换别的大小的small_chunk才能奏效。
（非常坑，因为源码级别看不出来这个问题，我调了好久跟着汇编指令走一遍才发现）
2. 构造ORW的ROP链，发现libc库的open函数不行，打不开文件而且程序直接崩掉，后面只能用syscall执行系统调用的open函数。

# 参考链接
[参考博客](https://blog.csdn.net/weixin_44145820/article/details/106245005)
[参考博客](http://blog.eonew.cn/archives/1263)
