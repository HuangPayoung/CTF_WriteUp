最近打算开始学习kernel pwn，整理一些其他师傅写的博客以及练习题目。


# 题目

## ciscn2017_babydriver

1. uaf修改creh结构体。
2. rop关闭smep保护后ret2usr。


## qwb2018_core

1. 使用rop在内核态实现提权。
2. 使用rop进行ret2usr攻击。


## 0ctf2018finals_babykernel

1. 利用多线程进行条件竞争，造成double fetch攻击。
2. 侧信道进行泄露，但是我本地调试每次重启后没有记录下save.txt文件，好像行不通。

[参考博客](http://p4nda.top/2018/07/20/0ctf-baby/)

难道要我每次重启前看日志输出然后自己创建save.txt？这也太奇怪了吧，有时候重启刷新太快了，非常考验手速。


## starctf2019_hackme

漏洞：pool数组编辑时存在越界可以造成任意读写。

任意地址读写修改`modprobe_path`变量，使其指向我们伪造的`/home/pwn/copy.sh`，当内核运行一个错误格式的文件时就会执行这个变量指向的可执行文件处，利用root权限将flag拷贝出来。


## xctf2020gxzy_babyhacker(2)

1. 经典ROP。
2. 学到一个偷鸡方法（不是），rm /sbin/poweroff，然后exit退出会找不到命令，返回的就是root shell。


## xctf2020gxzy_kernoob

第一个次做内核里面的堆题，学习了一些新的利用方法，以及内核的堆管理器slub的大致功能，slub管理器和fastbins类似都是利用fd指针来形成单向链表。

kernel当中关于堆分配器slub的两个保护措施，可以参考这篇博客[rtfingc](https://rtfingc.github.io/slub-freelist-hardened)。

简单的说：
1. `CONFIG_SLAB_FREELIST_HARDENED`保护是把fd位置加个随机值（canary）异或，举例：此时freelist为空，`kfree(heap0);kfree(heap1)`，则`heap0->fd == canary ^ heap0; heap1->fd === canary ^ heap1 ^ heap0`。所以如果希望改掉单向链表的话，必须先leak（两个）堆地址，依次释放这两个堆来leak canary。
2. `CONFIG_SLAB_FREELIST_RANDOM`保护是把freelist单向链表中各个堆块顺序打乱，未开保护之前freelist是把一个内存区域切成各个相同大小的堆块然后依次以单向链表链接起来，现在的话在链接成单向链表的时候会打乱顺序，所以取堆块的时候要小心了，多留心校验一下是不是真的取到伪造的堆块，这里就踩坑了。

攻击思路：

1. double fetch，开启恶意线程修改size为0x2e0，然后释放掉该堆块，打开`/dev/ptmx`设备，利用UAF修改该设备的`tty_operations`结构体，控制指针来rop，可以多开几个设备确保UAF那个恶意堆块被打开的文件拿到。
2. UAF直接利用，依次泄露堆地址和canary，然后篡改fd指向pool数组从而任意写。这里有个很秀的操作：如果直接把fd改成指向pool中的变量，该地址要么为0要么是kernel中的堆，内容不可控会导致`CONFIG_SLAB_FREELIST_HARDENED`的`prefech`检查不通过，所以伪造的fake_chunk要偏4字节，先在`pool[0x19]`处写一个4字节的fake_ptr（这个通过伪造magic来实现），然后伪造的fake_chunk指向&pool`[0x19] - 4`，就能在pool数组里面任意写了。申请的时候注意检查chunk里面内容，验证是否就是我们伪造的fake_chunk，我在这踩坑看了好久，也照着其他师傅的wp动态调了一遍发现没申请到，在内核里面环境可能会受各种情况影响，所以干脆写个循环多申请几个直到能确保申请到了fake_chunk。

参考链接：[bsauce](https://blog.csdn.net/panhewu9919/article/details/111839950) [kirin](https://kirin-say.top/2020/03/10/Kernoob-kmalloc-without-SMAP/)


# 环境搭建

其实题目一般会提供内核和相应的文件系统，里面都齐全了，但是为了调试还是自己准备一份比较好。


## kernel

参照ctf-wiki配置就行，采用内核版本为5.4.98。

唯一踩坑的地方是编译前`make menuconfig`这里的配置，我完全按照ctf-wiki配，但是后面qemu启动内核的时候一直重启，参照PIG-007师傅的这篇[博客](https://www.pig-007.top/2021/08/14/kernel%E7%BC%96%E8%AF%91/)关掉了一些编译选项，后面就能正常启动了。


## module

参照ctf-wiki写了一个内核模块，用Makefile编译，启动后在init脚本挂载上ko文件即可。

相关命令：
```
insmod: 将指定模块加载到内核中。
rmmod: 从内核中卸载指定模块。
lsmod: 列出已经加载的模块。
modprobe: 添加或删除模块，modprobe 在加载模块时会查找依赖关系。
```


## rootfs 

参照ctf-wiki编译busybox来构建一个文件系统，不过我采用版本为1.34.1（截至2021.10.24）最新版本。


# 常用命令

## packet

`find . | cpio -o --format=newc > ../rootfs.cpio`


## unpacket

如果经过gzip打包的话：`gunzip ./rootfs.cpio.gz`

解包得到文件系统：`cpio -idmv < rootfs.cpio`


## complie

内联汇编：`gcc exploit.c -static -masm=intel -g -o exploit`

多线程：`gcc -static exp.c -lpthread -o exp`


## gadget

`time ropper --file ./vmlinux --nocolor > g1`

`time ROPgadget --binary ./vmlinux > g2`

网上有师傅建议用ropper，但是我自己用的时候ropper一直卡着过不去，就用ROPgadget了。


## extract

`./extract-vmlinux ./bzImage > vmlinux`


## gdb

```
gdb ./vmlinux
add-symbol-file ./babydriver.ko 0xffffffffc0000000
b babyread
b *(0xffffffffc0000000+0x130)
target remote localhost:1234
```


# 参考链接

## 博客

[ctf-wiki](https://ctf-wiki.org/pwn/linux/kernel-mode/environment/build-kernel/)

[PIG-007](https://www.pig-007.top/categories/pwn-kernel/)

[m4x](https://m4x.fun/post/linux-kernel-pwn-abc-1/)

[b1b1](https://beafb1b1.github.io/kernel/linux_kernel_base/)

[钞sir](https://bbs.pediy.com/user-home-818602.htm)

[ERROR404](https://www.anquanke.com/post/id/201043#h3-20)


## 源码

[源码](https://elixir.bootlin.com/linux/v4.4.72/source/include/linux/cred.h#L118)

