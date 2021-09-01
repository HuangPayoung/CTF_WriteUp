64位堆题，仅开启NX和canary保护。增删查改四项功能，漏洞点在于删除后没有清空指针导致UAF漏洞。

# 程序分析
1. 展示功能，根据flag标志判断堆块是否存在，并依次打印。
2. 添加功能，用户任意指定size，但是申请时以0x80倍数对齐，也就没办法用fastbin_chunk。
3. 编辑功能，用户指定index和size，size不相等会调用realloc函数重新分配，然后再输入，同样以0x80对齐申请。
4. 删除功能，清空了flag和size，但是没有清空指针导致出现UAF漏洞，这个UAF只能用于double_free，其他功能没法使用。

# 攻击思路
1. 利用UAF漏洞实现double_free，从而构造堆叠，泄露libc和heap基址。
2. 知道heap基址后就能进行unlink攻击，因为指针存放在堆上。
