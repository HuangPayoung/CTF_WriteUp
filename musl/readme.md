最近刚学musl_libc的使用方法，整理几道题目到这。

~~等我有空了甚至想整个源码阅读分析~~

## 环境配置
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


## 参考链接

[musl 1.1.24 出题人角度解析](https://www.anquanke.com/post/id/202253#h2-9)

[musl 1.2.2 源码审计](https://www.anquanke.com/post/id/241101)

[musl 1.2.2 漏洞利用](https://www.anquanke.com/post/id/241104)

[musl-1.2.x堆部分源码分析](https://www.anquanke.com/post/id/246929)

[2021强网杯easyheap](https://www.anquanke.com/post/id/248411)
