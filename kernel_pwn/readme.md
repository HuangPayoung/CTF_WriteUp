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

难道要我每次重启前看日志输入然后自己创建save.txt？这也太奇怪了吧，有时候重启刷新太快了，非常考验手速。


## starctf2019_hackme

漏洞：pool数组编辑时存在越界可以造成任意读写。

任意地址读写修改`modprobe_path`变量，使其指向我们伪造的`/home/pwn/copy.sh`，当内核运行一个错误格式的文件时就会执行这个变量指向的可执行文件处，利用root权限将flag拷贝出来。


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


## 源码

[源码](https://elixir.bootlin.com/linux/v4.4.72/source/include/linux/cred.h#L118)

