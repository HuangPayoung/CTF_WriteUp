8.21-8.22的比赛，太菜了做了两道最简单的，以前总是打完比赛不总结不学习，感觉很不好。

所以打算从这次比赛开始，每次比赛，要么不打，要么打完都要看WP补充学习。


# 题目列表
总共10题做了2道，网上看其他师傅的WP最多有做6道的，缺的四道先传文件，后面要是能看到其他师傅的做法或者官方WP再回来补充。

## note
* say功能有一个scanf函数的格式化字符串漏洞，可以实现任意地址写。
* 没有free功能，先用格式化字符串漏洞改topchunk.size，然后用house_of_orange得到一个unsorted_chunk，就可以泄露libc。
* 往__realloc_hook写one_gadget，往__malloc_hook写realloc函数加上一个偏移，调整栈布局保证满足one_gadget的约束。

## PassWordBox_FreeVersion
* 第一次添加的时候可以泄露程序初始化中生成随机数。
* 添加的时候调用fgets函数多读取1个字节，导致off-by-null漏洞。
* 利用off-by-null构造堆叠，从unsorted_bin中把重叠的堆切成两部分，以满足两个指针指向同一chunk，利用保存unsorted_bin的地址泄露libc，然后用tcache_dup攻击伪造__free_hook的堆。



# 参考链接
[ChaMd5安全团队](https://mp.weixin.qq.com/s/EsLeJwmo0ylW_VDmHsW_gw)

[bad_cat](https://www.freebuf.com/articles/web/286171.html)
