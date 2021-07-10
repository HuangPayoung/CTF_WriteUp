64位下堆题，保护机制全开，增删查改4大功能，漏洞点在修改处，有一字节溢出。

功能介绍：

1、add，按照输入长度分配堆。

2、edit，指定index，输入size，当size比分配时的size大10时有1字节的溢出。

3、delete，释放申请的堆，清空指针无漏洞。

4、show，打印指定index的堆中信息。

攻击步骤：

1、利用1字节的漏洞构造堆叠，两指针指向同一chunk，利用放入unsorted_bin的堆来泄露libc基址。

2、同样利用堆叠，修改fastbin列表，将位于__malloc_hook前面的一个fake_chunk放入列表，然后申请出来进行修改。

3、往__realloc_hook写one_gadget，往__malloc_hook写relloc函数的地址，参考下图.
总共有6条push指令，另外rsp-0x38，将__realloc_hook取出并赋值给rax，还有一条call指令，全部执行的话栈会抬高0x70，为配合本题的one_gadget跳过了两条push。

![realloc_1](https://github.com/HuangPayoung/CTF_WriteUp/edit/master/BUUCTF/pwn/roarctf_2019_easy_pwn/realloc_1.jpg)

![realloc_2](https://github.com/HuangPayoung/CTF_WriteUp/edit/master/BUUCTF/pwn/roarctf_2019_easy_pwn/realloc_2.jpg)

做这题学到了新东西，之前只会在__malloc_hook中写one_gadget，做这题因为栈布局几个one_gadget都不能正常使用，最后一步当中使用realloc来调整栈布局，参考两位师傅的博客。
[博客](https://blog.csdn.net/mcmuyanga/article/details/111307531?utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.control)
[博客](https://bbs.pediy.com/thread-246786.htm)
