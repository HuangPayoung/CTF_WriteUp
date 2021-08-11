64位下堆题，glibc版本2.23，保护机制全开，有增删改三项功能，没有展示功能，漏洞点在于删除后没有清空指针导致UAF漏洞。

# 攻击思路
1. 由于没有打印功能，且开了Full RELRO没法改got表，所以用stdout来进行信息泄露。
2. 利用UAF修改fastbin_chunk->fd造成堆叠，然后修改原先0x70大小的堆为0xe1，并放入unsorted_bin，修改低2字节使其指向stdout结构体附近的fake_chunk（高4位需要爆破），然后修改stdout以泄露libc基址。
3. fastbin attack，修改fd指针至__malloc_hook附近，写入one_gadget，需要用realloc调整栈布局。
