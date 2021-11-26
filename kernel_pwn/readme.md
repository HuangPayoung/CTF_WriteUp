最近打算开始学习kernel pwn，整理一些其他师傅写的博客以及练习题目。


# 题目

## ciscn2017_babydriver

1. uaf修改cred结构体。
2. rop关闭smep保护后ret2usr。


## qwb2018_core

1. 使用rop在内核态实现提权。
2. 使用rop进行ret2usr攻击。


## 0ctf2018finals_babykernel

1. 利用多线程进行条件竞争，造成double fetch攻击。
2. 侧信道进行泄露，但是我本地调试每次重启后没有记录下save.txt文件，好像行不通。

[参考博客](http://p4nda.top/2018/07/20/0ctf-baby/)

~~难道要我每次重启前看日志输出然后自己创建save.txt？这也太奇怪了吧，有时候重启刷新太快了，非常考验手速。~~

受另外一道题目`d^3ctf2019_knote`启发，其实可以用sleep来阻塞一下，然后就能看到每次爆破的最后结果。


## starctf2019_hackme

漏洞：pool数组编辑时存在越界可以造成任意读写。

任意地址读写修改`modprobe_path`变量，使其指向我们伪造的`/home/pwn/copy.sh`，当内核运行一个错误格式的文件时就会执行这个变量指向的可执行文件处，利用root权限将flag拷贝出来。


## xctf2020gxzy_babyhacker(2)

1. 经典ROP。
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


## d^3ctf2019_knote

内核题调试起来好麻烦，学到一个条件竞争的新方法，利用`userfaultfd`这个方法来阻塞进程，从而保证条件竞争成功。原理可以看ha1vk师傅写的博客很详细，另外他还提供一个注册handler函数的模版。

攻击思路：
1. 写一个handler函数处理缺页错误，处理过程和原过程类似分配新的内存页给缺页，需要修改的地方是新内存页的内容以及加一个sleep函数阻塞该进程。
2. 用mmap申请一页内存，然后对该页内存注册handler函数，虽然mmap申请了但是还没使用过，实际上并没有分配该页内存，传入内核使用的话就会报缺页错误。
3. 父进程调用kshow传入mmap申请的那页内存，出现缺页错误进入handler函数处理。子进程sleep(1)保证父进程先执行，父进程处理缺页然后sleep(3)。执行回到子进程（还剩2s足够了），此时调用kdelete释放kshow的目标堆，再open("/dev/ptmx")使得刚刚释放的堆被tty_struct结构体拿到，从而造成UAF漏洞，然后子进程exit(0)退出。执行回到父进程，kshow的目标堆已被换成tty_struct结构体，此时kshow就能拿到里面的指针从而泄露内核基址。
4. 后续攻击思路也类似，利用UAF修改释放堆的FD指针，从而实现任意内存分配，尝试分配到modprobe_path变量的地址，然后利用kedit改成我们自己编写的catFlag脚本。
5. 执行错误文件然后就会调用`__request_module`函数去执行`ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);`，此时`module_name`就是我们修改的恶意脚本，然后就能`cat flag`。
6. 踩坑点：一开始cat flag完成后直接退出了，然而我们分配的fake_chunk程序结束后会被释放，导致内核直接崩掉，~~虽然flag输出了但是手速不够快总是看不到flag~~，所以可以在退出前加个sleep阻塞进程保证能看到flag。

参考链接：[ha1vk](https://blog.csdn.net/seaaseesa/article/details/104650794) [pkfxxx](https://pkfxxxx.github.io/2020/03/19/ji-lu-yi-dao-kernel-pwn/)


## qwb2021_notebook

和上面d^3ctf的knote一样，也是采用`userfaultfd`这个方法来协助实现条件竞争。

攻击思路：
1. 分配`tty_struct`结构体大小的堆块，然后利用`noteedit`指定size为0将其释放掉。因为在保存指针前有一个`copy_from_user`函数，所以可以传一个未初始化的内存页然后利用handler函数将其卡住，保证后面的指针清空操作不执行，导致UAF。
2. editnote后`note指针`没被修改但是`size域`已被改为0，和上面的思路一样，调用`noteadd`函数把size改回0x60，同样利用`copy_from_user`函数然后触发handler函数卡住该进程，保证后面的指针赋值操作不执行。
3. 内核的堆管理机制比较奇怪（有空好好研究一下），用堆喷射技术重复打开`/dev/ptmx`设备，保证刚刚释放的堆块被申请为`tty_struct`结构体，然后利用里面的指针泄露内核基址。
4. 修改`tty_struct`结构体的`vtable`虚表指向我们在堆上的可控空间（题目有个`notegift`函数能泄露堆地址），然后利用`ioctl(tty_fd, 233, 233);`和`ptmx`设备交互调用函数指针，实现控制流劫持。
5. 控制流劫持方法：网上看到有师傅用传统的ROP技术来劫持控制流，但是很繁琐要绕各种防护还要多次栈劫持，长亭的师傅找到一个非常好用的gadget，可能是他们之前搞内核的技术经验积累吧，要是比赛期间找到的那可太牛逼了。引用他们的描述：
```
struct work_for_cpu
{
    struct work_struct work;
    long (*fn)(void *);
    void *arg;
    long ret;
};

static void work_for_cpu_fn(struct work_struck *work)
{
    struct work_for_cpu *wfc = container_of(work, struct work_for_cpu, work);
    wfc->ret = wfc->fn(wfc->arg);
}

```
由二进制反编译的代码：
```
__int64 __fastcall work_for_cpu_fn(__int64 a1)
{
    __int64 result;

    _fentry__(a1);
    result = (*(__int64 (__fastcall **)(_QWORD))(a1 + 32)(*(_QWORD *)(a1 + 40)));
    *(_QWORD *)(a1 + 48) = result;
    return result;
}
```
从反编译的代码里面可以清晰看到，只要能控制第一个参数，就能劫持控制流，以偏移32的8字节为函数指针，以偏移40的8字节作为第一个参数，同时会把返回结果保存在偏移48的位置。

`token = prepare_kernel_cred(0); -> commit_creds(token);`，劫持控制流后，分两步实现提权。


参考链接：[ctf-wiki](https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/userfaultfd/) [长亭](https://zhuanlan.zhihu.com/p/385645268) [墨晚鸢](https://www.anquanke.com/post/id/253835#h2-0)

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

多线程：`gcc -static exp.c -pthread -o exp`


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

