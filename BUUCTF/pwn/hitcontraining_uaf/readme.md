堆题，增删查三大功能，其中删除功能没有清空指针存在use-after-free漏洞，另外打印功能的函数指针放在了堆上，能被篡改。

攻击思路：

1、申请两个note，其中两个管理堆，两个数据堆。

2、将两个note都释放，四个堆各自放入相应的bins当中。

3、申请新note，其中数据堆大小刚好和管理堆一样，从而能够在管理堆上将打印函数指针覆盖成后门函数。

4、利用use-after-free漏洞，调用note0的打印功能，此时已被覆盖成后门函数，从而直接拿到shell。
