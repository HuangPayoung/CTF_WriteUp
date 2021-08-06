64位下堆题，保护机制全开，而且有沙箱没法拿shell，增删查改四项功能都有，漏洞点在于删除时没有清空指针。

程序分析：
1. 初始化，设置IO和沙箱，另外申请了一个0x1000的堆，后面有用处。
2. 后门函数，菜单输入666时，会对最初申请的堆进行一些条件判断，偏移0x800处的值要大于0x7f0000000000，偏移0x7f8处和0x808处的值必须为0，然后存在一个栈溢出，能覆盖RBP和RIP，要用栈劫持。
3. 添加功能，用calloc申请堆块，index任意指定无检查，最多能添加0x1c次，大小可选择0x10，0xf0，0x300，0x400四种，同时会往新堆块中写入指定size的数据。注意calloc函数不会从tcache中拿chunk。 
4. 删除功能，指定index释放堆块，没有清空指针导致UAF漏洞。
5. 修改功能，指定index修改该堆块内容，能输入申请时的长度，修改功能只能调用一次。
6. 打印功能，指定index打印该堆块内容。

攻击思路：
1. 先用7个0x410的堆填满tcache，再放1个进unsorted_bin，利用UAF漏洞泄露heap基址和libc基址，同时放6个0x100的堆进tcache，为后面攻击作准备。
2. 构造堆布局，把0x410的堆放入unsorted_bin，然后申请0x310的堆进行切割，剩下0x100暂时放入unsorted_bin，申请一个大的就能使得该堆整理进对应的smallbins，重复两次放两个进0x100的smallbins。
3. 使用tcache_stashing_unlink_attack攻击，0x100的smallbin2是由0x410切割而来的，用UAF造成的堆叠修改其bk域为（target - 0x10）。然后calloc申请0x100的堆时不会去tcache中拿，
从smallbins（0x100）中拿出smallbin1，smallbin2被整理进tcache，bck（target - 0x10）-> fd 被赋值为libc中main_arena的smallbins地址，这样后门就能用了。
4. 在堆上布置ROP链，通过后门函数的栈溢出把栈劫持到堆上，调用顺序：open，read，puts。文件名和读写缓冲区布置在堆上即可。

[参考博客](https://blog.csdn.net/weixin_44145820/article/details/106245005)
