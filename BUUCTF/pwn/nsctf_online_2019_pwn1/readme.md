64位堆题，保护机制全开，增删改三项功能，漏洞点在于修改时有一个下标越界和off-by-null漏洞。

# 攻击思路
1. 由于没有打印功能，利用下标越界修改bss段上的stdout结构体，以泄露libc。
2. 利用off-by-null构造堆叠，然后进行fastbin_attack。
