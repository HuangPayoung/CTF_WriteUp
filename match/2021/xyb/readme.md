8.21-8.22的祥云杯，太菜了做了两道最简单的，以前总是打完比赛不总结不学习，感觉很不好。

所以打算从这次比赛开始，每次比赛，要么不打，要么打完都要看WP补充学习。

# 题目列表

总共10题做了2道，网上看其他师傅的WP最多有做6道的，缺的4道先传文件，后面要是能看到其他师傅的做法或者官方WP再回来补充。

## note

* say功能有一个scanf函数的格式化字符串漏洞，可以实现任意地址写。
* 没有free功能，先用格式化字符串漏洞改topchunk.size，然后用house_of_orange得到一个unsorted_chunk，就可以泄露libc。
* 往__realloc_hook写one_gadget，往__malloc_hook写realloc函数加上一个偏移，调整栈布局保证满足one_gadget的约束。

## lemon

* game功能，输入111111可以通过。把flag存在栈上，利用输入name的时候提前在栈上伪造lemon结构体。
* 修改功能，检测下标没有检查负数，指定下标为-260，就可以利用存放在数据段上的栈地址进行修改，导致栈溢出，把argv[0]程序名覆盖成flag地址，覆盖2字节，其中高4位需要爆破，有1/16的几率中。
* 添加功能，用户指定size大于0x400就不会正常分配，但是没有清空指针导致UAF。
* 利用UAF实现double_free，然后篡改tcache链表指向一个不合法地址（size域和用户申请size不相等）
* 申请该fake_chunk，程序检查不通过，就会将其释放，size无法通过free函数的检查，报错打印argv[0]并退出。

## PassWordBox_FreeVersion

* 第一次添加的时候可以泄露程序初始化中生成随机数。
* 添加的时候调用fgets函数多读取1个字节，导致off-by-null漏洞。
* 利用off-by-null构造堆叠，从unsorted_bin中把重叠的堆切成两部分，以满足两个指针指向同一chunk，利用保存unsorted_bin的地址泄露libc，然后用tcache_dup攻击伪造__free_hook的堆。

## PassWordBox_ProVersion

* UAF漏洞，可任意使用，但是用户申请大小要求为[0x420, 0x888]。
* [2.31版本的large_bin_attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/large_bin_attack.c)，参考how_to_heap的攻击方法。
* 利用large_bin_attack修改mp_结构体mp_.tcache_bins和mp_.tcache_max_bytes这两个成员，相当于之前攻击global_fast_max一样的思路，增大了tcache_chunk的使用范围。
* 利用UAF进行tcache_dup攻击。

## JigSaw'sCage

* 初始化输入chioce的时候，读入8字节（%ld），能把保存在站上的random_number给覆盖掉，导致堆段可执行。
* 添加功能，申请固定大小0x10，然后填满（\xc3）ret指令；编辑功能，最多输入0x10大小内容，但是第0xf字节总会被覆盖成ret指令；执行功能，以保存在各个chunk的内容为指令，开始执行。
* 由于每次15字节执行写的shellcode，太短没法一次性实现攻击，所以要布置多个chunk然后串起来执行（最多允许申请5个）。
* 攻击流程：
    1. 栈劫持：注意到堆地址通过rdx寄存器传参，可以用rdx给rsp赋值。
    2. 串联多个shellcode：在执行每段shellcode末尾，加上`add rsp, 0x20; push rsp`，由于程序提供了ret指令，就能够成功跳转到下一段shellcode执行，同时控制了rip和rsp。
    3. 在堆上写'/bin/sh'然后赋值给rdi，清空rsi和rdx，最后调用syscall。

## babymull

1. 没有清空释放chunk的内容，再次申请利用show功能泄露mmap和libc基址。
2. 利用后门功能泄露secret，并利用一字节将mmap段上申请的大堆块里面的offset覆盖掉。
3. 依次在mmap段上伪造group、meta、meta_area，然后释放被篡改的堆，利用nontrivial_free()里面的queue()将meta放入active数组。
4. 利用堆叠，修改伪造的meta->mem指向stdout，在堆上布置ROP链，然后进行FSOP劫持控制流，利用栈劫持来控制流劫持到ROP链上拿到flag。


# 参考链接

[官方WP](https://mp.weixin.qq.com/s/UwrZVlQ_WJ5rO4InOErt1g)

[ChaMd5安全团队](https://mp.weixin.qq.com/s/EsLeJwmo0ylW_VDmHsW_gw)

[bad_cat](https://www.freebuf.com/articles/web/286171.html)
