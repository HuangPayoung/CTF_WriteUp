64位下elf文件，保护机制全开，增删查改四项功能，漏洞点在于删除后没有清空指针导致UAF漏洞。

攻击思路：
1. 构造堆布局，将堆块放入fastbins单向链表，用UAF漏洞泄露libc基址。
2. 在堆上伪造fake_chunk头部，然后修改fastbins中的链表分配一个fake_chunk，能够控制真实堆块的头部。
3. 修改堆块头部至unsorted_bin范围内，释放后泄露libc基址。
4. fastbins攻击，在__malloc_hook附近伪造fake_chunk并写入one_gadget。
