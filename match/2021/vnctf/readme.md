看博客看到一篇写glibc 2.32的文章，提到了这个比赛，就顺便把几道题给摸了，不是很难。


# 题目

## ff

第一次做glibc 2.32的题目，其实和31差不多，就是多了一个异或保护还有对齐检查，所以打tcache的时候要考虑这点，不过这也有利于泄露heap_base。


## hh

官方wp用偏移来做好麻烦，puts打印东西会在栈上残留IO FILE指针，我用这个来泄露libc，然后栈劫持ORW。


## LittleRedFlower

glibc 2.30，tcache 有个`mp_`结构体里面记录一些tcache的控制信息，改掉就可以扩大tcache的申请范围，类似fastbin打`global_max_fast`，然后栈迁移ORW。


## White_Give_Flag

read函数读取失败会返回-1，然后用这个来越界读，很傻逼就嗯爆破。


# 参考链接

[官方wp](https://mp.weixin.qq.com/s/1OzuKnQK2wNxhHYObN3UYA)
[墨晚鸢](https://www.anquanke.com/post/id/236186#h2-3)
