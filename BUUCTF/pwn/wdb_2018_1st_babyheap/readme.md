64位堆题，除了PIE其他保护机制全开，增删查改功能都有，漏洞点在于删除后没有清空指针。

# 攻击思路
1. 利用UAF漏洞，泄露heap基址，并修改fastbin链表伪造fake_chunk，造成堆叠。
2. 修改chunk->size为0x90，使用unlink攻击。
3. 控制ptr_list，往__free_hook写system函数，然后释放一个/bin/sh堆块。
