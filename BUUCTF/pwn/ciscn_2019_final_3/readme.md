64位下堆题，保护机制全开，libc版本位2.27，有tcache机制。

程序功能：

* 添加，可申请<=0x78字节的堆块，并在添加的过程中修改堆块内容，最后打印堆地址
* 删除，直接删除堆块，但是没清空指针，存在UAF漏洞

攻击思路：
1. 泄露libc需要将堆块放入unsorted_bin或者small_bins，但是题目限制了堆块大小，这个大小就算不放入tcache也会放入fastbins。
所以首先要利用tcache的 double free 漏洞篡改tcache的单向链表，根据打印的堆地址将fake_chunk分配到堆的头部，然后修改其大小。
注意，由于tcache机制的存在，即便堆的大小超过fastbin限制也会先放入tcache，所以要连续释放7个先把tcache填满，然后才能到unsorted_bin当中。
2. 放入unsorted_bin之后，根据利用堆布局，先取unsorted_bin中的堆块的前一部分，剩下一部分仍在unsorted_bin当中，保留着libc地址。另外通过堆叠使得剩下那一部分链入tcache的单向链表。
由于本题不提供打印功能，只能在申请的时候打印堆块地址，所以还要通过申请的方式申请在unsorted_bin处的堆块，这样才能泄露地址。
3. 由于申请了在unsorted_bin处的堆块，会破坏unsorted_bin的结构，所以后面要注意不能访问unsorted_bin程序会直接崩溃，所以为了后续的利用在前面提前申请一块0x70的堆块，用来实现tcache的double free攻击。
4. 和第2步类似构造tcache的double free，然后将__malloc_hook处的fake_chunk链入tcache链表，申请到该fake_chunk后写入one_gadget。


[参考博客](https://blog.csdn.net/github_36788573/article/details/103599951)
