32位下的堆题，开启了canary和N保护机制，增删查改四大功能，漏洞在修改时长度检查有问题，会导致堆溢出。

user的数据结构
```C
struct user{
    char *description;
    char name[0x7c];
}
```

功能描述：

* 添加user，先malloc用户指定的长度申请description，然后malloc申请一个user结构，之前申请的description指针放前4字节，
然后读取最多124字节到name，并调用update更新description，最后把user指针保存在user_list数组当中。

* 删除user，指定index，依次free掉description和user两个堆块，且清空指针，无漏洞。

* 打印user，指定index，打印user结构中的name以及description。

* 修改user，指定index以及要输入内容长度size，对size有一个检查但是这个检查有问题，IDA反汇编出来的代码看不懂，参考他人的博客我举例描述一下我的理解。

这个检查机制似乎只考虑了，先申请desc堆块然后申请user堆块是物理相邻的下一个堆块，这一情况：

`(char *)(user_list[index]->description) + size < (char *)(user_list[index]) - 4`

就是写的地址最长能到user堆块的prev_size域。

攻击思路：

1. 先申请三个user，堆布局如下；

\## user0.desc \## user0.strc \## user1.desc \## user1.strc \## user2.desc \## user2.strc \##

2. 删除user0，前两个堆块合并放入unsorted_bin当中，堆布局如下；

\## free_chunk(unsorted_bin) \## user1.desc \## user1.strc \## user2.desc \## user2.strc \##

3. 申请free_chunk大小的desc，使得新的user堆会在末尾top_chunk处切割出来，堆布局如下：

\## user3.desc \## user1.desc \## user1.strc \## user2.desc \## user2.strc \## user3.strc \##

4. 此时检查机制失效，可以覆盖掉中间几个堆，篡改user1.strc中的desc指针，改为free_got，用来泄露libc基址，然后把free_got改成system函数，释放掉准备好的/bin/sh堆块。

[参考博客](https://blog.csdn.net/qinying001/article/details/104359401)
