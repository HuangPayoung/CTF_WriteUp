最近刚学musl_libc的使用方法，整理几道题目到这。

~~等我有空了甚至想整个源码阅读分析~~

# 环境配置

配了1.1.24和1.2.2这两个版本，都带了符号信息，也支持源码调试。

配环境参考了XCTF_2020_PWN_musl/source/build.sh脚本。
```
wget https://musl.libc.org/releases/musl-1.2.2.tar.gz
tar -xzvf ./musl-1.2.2.tar.gz
cd musl-1.2.2
mkdir -p build
./configure --enable-debug --prefix="/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build" --syslibdir="/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib"
make -j$(nproc)
make install
```
lib目录下有libc.so，一个ld符号链接指向libc.so，bin路径下有一个musl-gcc可以用来编译源码（如果有的话）。

# 题目列表

## XCTF_2020_PWN_musl

第一个题目就是这个了，配环境配了好久以为是自己搞错了，编译完一运行就是段错误。结果发现是fix后的源码有问题，不是我环境的问题，气死我了，最后用没有fix的源码来编译一个出来。

出题的师傅博客已经写的非常详细了，不过我用的是带调试信息版本的libc，所以偏移有所不同，也花了非常多时间才调了出来，还是太菜了org。有源码了逆向也比较轻松，简单整理一下攻击流程。

### 攻击思路
1. musl的堆是静态内存（从libc和elf中抠出一些不用的内存），不够再动态申请分配。先添加一个小的堆，利用残留在堆中的bin地址和仅有一次的view泄露libc。
2. musl调用unbin函数取出堆脱链的时候没什么检查，唯一要保证的是next和prev两个字段`c->prev->next = c->next;c->next->prev = c->prev;`，也就是prev+0x10和next+0x18要可写。
3. 伪造3个fake_chunk: (stdin - 0x10), (brk - 0x10), (binmap - 0x20)，用仅有一次的堆溢出造成mal.bins[0]链表失效，然后可以重复利用unbin的任意地址写，往这3个fake_chunk的next和prev指针写上自身地址。
4. 利用unbin往mal.bins[37].head写fake_chunk地址，申请一个大的（0x50）就会去该链表切出来，重复3次拿到3个fake_chunk。
5. 改binmap为0伪造bins中没有chunk的假象，这样就会调用expand_heap函数延展堆内存空间。
6. 改全局变量brk，这里有坑，一开始我用`p brk`其实找到的是函数不是全局变量brk，然后跟进expand_heap函数发现其实变量名是brk.2083（可能brk名称被brk函数占据了？）。把brk改成0xbadbeef-0x20，下次申请0x20的堆就会返回0xbadbeef的地址。
7. 改stdin进行FSOP攻击，调用exit()函数就会触发。


## WMCTF_2021_Nescafe

1.1.24版本的musl，保护机制全开，另外还有沙箱不能拿shell，漏洞点在于释放后没有清空指针导致UAF。

### 攻击思路
1. 利用仅有一次的show泄露libc基址。
2. 利用unbin进行任意地址写，伪造指向(__stdout_FILE - 0x10)的fake_chunk，先用unbin改它的next和prev指针，然后任意地址写写进mal.bins[16]，下次申请就能拿到。
3. 在堆在布置ROP链（ORW），因为堆在libc内部所以泄露了libc其实就知道了heap中各个chunk地址。
4. 类似FSOP，修改stdout，这里用到一个非常好用的gadget：long_jmp。相当于只要控制了一个rdi寄存器就可以控制其他多个寄存器（包括rsp），本题中只用0x4951a开始的部分即可，劫持rsp以及控制流。
```
.text:0000000000049503 loc_49503:
.text:0000000000049503 mov     rbx, [rdi]
.text:0000000000049506 mov     rbp, [rdi+8]
.text:000000000004950A mov     r12, [rdi+10h]
.text:000000000004950E mov     r13, [rdi+18h]
.text:0000000000049512 mov     r14, [rdi+20h]
.text:0000000000049516 mov     r15, [rdi+28h]
.text:000000000004951A mov     rdx, [rdi+30h]
.text:000000000004951E mov     rsp, rdx
.text:0000000000049521 mov     rdx, [rdi+38h]
.text:0000000000049525 jmp     rdx
.text:0000000000049525 longjmp endp
```
5. 第一次劫持先把rsp劫持到stdout结构体当中，调用puts函数会使用结构体里的指针从而劫持控制流；第二次劫持把rsp劫持到堆上布置好的ROP链从而获取flag。

### 踩坑
一开始我想着劫持一次rsp就行，直接把ROP链放在stdout结构体中，然后一直卡着过不去，puts有一个加锁函数然后在调用fputs函数，就这个加锁的过程一直过不去。后面调试的时候就把ROP链一点一点改短，发现就可以了，可能是加锁的时候会用到stdout结构体里面的变量，所以第一次劫持rsp到stdout结构体里面不能写太长，我就想了另外的方法把ROP链放堆上，再用一次long_jmp劫持过去。


## BSides_Noida_CTF_2021_baby_musl

学到新的劫持控制流的方法。

```
_Noreturn void exit(int code)
{
	__funcs_on_exit();
	__libc_exit_fini();
	__stdio_exit();
	_Exit(code);
}
```

之前FSOP是控制第三个函数里面的流程，这次是第一个函数里面的流程。

```
void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	LOCK(lock);
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		UNLOCK(lock);
		func(arg);
		LOCK(lock);
	}
}
```

head变量可读写，初始值为0，不能直接`libc.sym['head']`去找这个符号，会找成另外一个，要利用偏移`libc.sym['environ'] + 0x20`。

payload构造：`payload = p64(fake_fl) + b'A' * 0xf8 + p64(system) + b'A' * 0xf8 + p64(bin_sh)`，fake_fl变量以及head变量写payload存放的地址。


## DefCon_Quals_2021_mooosl

第一次看1.2.2的题目，太太太太恐怖了，这题真的搞了我快一周了吧，反复看源码反复gdb调试，不过做完也有很大的收获。

### 1.2.2新版特性

1.2.2关于malloc管理方面发生翻天覆地的变化，和1.1.24版本几乎没有任何关联，因为内容太多了，我现在只整理和漏洞利用相关的内容，后续如果对源码有深入阅读和理解再做一个完整的整理。

管理数据结构：
```
__malloc_context(位于libc中bss段上)
->meta_area(新申请一页保证地址末12位对齐，一般就是0x56的heap段)
->meta(一般都是从elf或者libc扣出一些内存片)
->group(mmap申请，一般0x7f，和上述结构分离开，看情况有可能可以用这个地址来泄露libc，因为mmap申请的内容和libc似乎有固定偏移)
```

group对chunk的管理策略：
1. chunk按照内存先后（也就是avail_mask），依次分配。
2. free掉的chunk被记录在free_mask，不能马上分配。
3. 需要等group内所有chunk都处于freed或者used状态时，此时avail_mask为0，下次申请会将freed状态的chunk转换成avaliable。

### 攻击思路
1. 利用UAF泄露地址信息和secret，注意要构造好堆风水，使得原先用来保存value的堆被写入指针。
2. 伪造meta->next/prev指针，利用unlink时调用dequeue函数可以任意地址写，往__stdout_FILE写伪造的meta地址。
3. 利用queue函数把伪造的mete放入__malloc_context的active数组当中，下次申请即可拿到。
4. 进行FSOP攻击拿到shell。


## RCTF_2021_musl

最近一直在学musl，刚好这周末RCTF就碰上了一道1.2.2的题目，摸了一道。其他题目太难了，一道都做不出来，人麻了。

### 攻击思路
1. 申请size为0时有一个堆溢出，构造堆风水来泄露信息。
2. 和DefCon那一道差不多也是伪造meta，但是开了沙箱没法拿shell，所以栈迁移至堆上的ROP链进行ORW。
3. 比较坑的一点是这个题目用flag的目录来恶心你，告诉你在/home/ctf/flag/路径下，但是flag文件名称有问题，然后我就搞不动了。后面队友帮忙补上，先用open('/home/ctf/flag/', 0x1000, 0)打开这个路径，然后用getdents(3, buf, 0x40)把目录下的文件名读到buf上，最后write打印出来。接下来是常规的ORW了。


## RCTF_2021_warmnote

比赛的时候没注意原来还有一道musl，复现其他大佬的WP。

### 攻击思路
1. 构造堆风水，利用释放note时没有清空内容来泄露信息，再利用后门泄露secret。
2. 利用edit的溢出覆盖掉offset字节，伪造group, meta, meta_area，利用dequeue函数实现任意地址写。
3. 重新申请以拿到伪造的meta，然后利用堆叠控制meta，从而拿到stdout结构体进行FSOP。
4. 通过FSOP控制程序流，由于开了沙箱，只能栈劫持至ROP链上进行ORW。

## xyb_2021_babymull

整理祥云杯的题目顺便有一题musl。

### 攻击思路
1. 没有清空释放chunk的内容，再次申请利用show功能泄露mmap和libc基址。
2. 利用后门功能泄露secret，并利用一字节将mmap段上申请的大堆块里面的offset覆盖掉。
3. 依次在mmap段上伪造group、meta、meta_area，然后释放被篡改的堆，利用nontrivial_free()里面的queue()将meta放入active数组。
4. 利用堆叠，修改伪造的meta->mem指向stdout，在堆上布置ROP链，然后进行FSOP劫持控制流，利用栈劫持来控制流劫持到ROP链上拿到flag。


## 5space_2021_notegame

日常自闭，复现队伍大佬的WP。

### 攻击思路
1. 利用realloc的特性，会把旧堆块的内容拷贝至新堆块，用来泄露mmap/libc基址，并利用后门泄露secret。
2. 利用tempNote功能，在指定地址自己伪造meta_area, meta。
3. 利用edit功能的溢出清空下一堆块的offset，然后伪造group使其指向伪造的meta。
4. 利用dequeue函数的unlink功能任意写，将__stdout_used变量覆盖成tempNote申请的区域上，在该内存中伪造stdout。
5. exit退出，通过FSOP获取shell。

# 参考链接

[musl 1.1.24 出题人角度解析](https://www.anquanke.com/post/id/202253#h2-9)

[musl 1.1.24 exit劫持控制流](https://niebelungen-d.top/2021/08/22/Musl-libc-Pwn-Learning/)

[musl 1.2.2 源码审计](https://www.anquanke.com/post/id/241101)

[musl 1.2.2 漏洞利用](https://www.anquanke.com/post/id/241104)

[musl-1.2.x堆部分源码分析](https://www.anquanke.com/post/id/246929)

[新版musl-libc malloc源码分析与调试](https://www.anquanke.com/post/id/252293#h2-0)

[2021强网杯easyheap](https://www.anquanke.com/post/id/248411)
