64位下elf文件，开启NX和canary保护机制，增删改三项功能，漏洞点在于删除功能没有清空指针。

程序分析：
1. 添加功能，ptrlist可存放16个指针，但是有一个全局变量addcnt总共只能申请9次。申请时可指定下标，只能申请0x80大小的堆块，同时在flags数组中作标记表示已分配。
2. 编辑功能，全局变量cnt为0总共只能改一次，指定下标编辑该指针，没有检查flags数组中的标记，结合删除时没有清空指针，导致UAF漏洞。
3. 删除功能，指定下标释放该指针，会在flags数组中清除标记，但是没有清空指针。
4. 后门，先用calloc申请0x70大小的堆。然后判断全局变量ptr，不为0则返回shell。

攻击流程：
1. 申请7个堆（chunk0-chunk6）并依次释放，先将tcache填满，然后放一个chunk7进fastbins当中。
2. 修改fastbins中堆块的fd域，指向ptr-0x10。申请一个堆，此时会优先从tcache中拿出一个，使得tcache不满。
3. 调用后门，calloc的时候不会从tcache中拿堆，则从fastbins中拿出chunk7，然后将fake_chunk放入tcache，则ptr被赋值为tcache5，不为0，成功调用后门。

踩坑点：
一开始希望用tcache单链表伪造一个fake_chunk指向ptr然后直接修改，但是实际上总共只能修改一次，哪怕用fake_chunk指向全局变量cnt也不行，因为改的那一次要用在tcache或者fastbins当中。

[参考博客](https://www.cnblogs.com/luoleqi/p/13473995.html)
