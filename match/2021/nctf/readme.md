周末忙里偷闲摸了个比赛，~~dragon_ctf看起来好像很难就懒得看了~~。

师傅们出的题目挺好的，又学到了一些新姿势。


## ezheap

确实ez，一般叫ez不是应该巨难吗（不是），考2.33的新特性，UAF很好用。


## house_of_fmyyass

这题有点恶心，限制太多了。

`__malloc_hook`和`__free_hook`全ban，main函数不返回，也没`exit`只用`_exit`，后者用系统调用直接退出没法刷新IO，而且交互只用`read``write`没办法利用这个来劫持控制流，想着触发glibc的abort流程，后面发现2.27以后abort里面也不刷新IO了。

感觉像`house_of_emma`那题，但是又把`stderr`放elf的bss段上不在libc里面了，最后实在想不出来。

攻击思路：
1. 泄露libc和mmap段基址，重复用largebin_attack往各个目标写入mmap段上的堆地址。
2. 写`_IO_list_all`然后伪造IO结构体，写`fs:[0x30]`为已知的mmap地址，和`house_of_emma`一样的攻击手法。
3. 往`__printf_arginfo_table`和`__printf_function_table`两个地址写入mmap地址，这其实是`house_of_husk`攻击，之前我看过[PIG-007师傅](https://bbs.pediy.com/thread-269155.htm)的博客，其实就是利用`printf`函数可以自定义格式化字符的特性（比如原先的%s，%d这类），在偏移写上`_IO_cleanup`函数，强行刷新IO我服了。
4. 改`top_chunk`触发__malloc_assert报错，然后`__fxprintf`打印时触发控制流。


调用流如下：~~pwndbg一页的调用栈7个函数不够放我的天~~

```
    f 0   0x7ffff7e492f0 __vfprintf_internal
    f 1   0x7ffff7e52d38 locked_vfxprintf+312
    f 2   0x7ffff7e52fc8 __fxprintf+248
    f 3   0x7ffff7e52fc8 __fxprintf+248
    f 4   0x7ffff7e671f2 __malloc_assert+66
    f 5   0x7ffff7e69914 sysmalloc+1860
    f 6   0x7ffff7e6a76f _int_malloc+3375
    f 7   0x7ffff7e6d8d5 calloc+133
```

```
    f 0   0x7ffff7e24a60 system
    f 1   0x7ffff7e63d4a _IO_flush_all_lockp+250
    f 2   0x7ffff7e63fa9 _IO_cleanup+41
    f 3   0x7ffff7e483fb printf_positional+5659
    f 4   0x7ffff7e4ad56 __vfprintf_internal+6758
    f 5   0x7ffff7e4bc20 buffered_vfprintf+192
    f 6   0x7ffff7e4a9c9 __vfprintf_internal+5849
    f 7   0x7ffff7e52d38 locked_vfxprintf+312
```


## login

标准输出加标准错误全关了，溢出只能控到rip要栈劫持，这题我是没做出来。

攻击思路：
1. 第一次写入触发栈溢出，覆盖rbp栈劫持到bss段上，覆盖rip为read前的位置再次读入。
2. 劫持控制流后进行第二次读入，在fake_stack上利用csu布置rop链。
3. rop链分3步：先改close_got，低字节写成`syscall`指令；然后利用read函数返回值存放在rax的特性控制rax为0x3b；最后调用（close_got）相当于syscall获取shell。
4. 第二次读入同样覆盖rbp再次栈劫持，这次才能控制到rsp然后劫持至上面的rop链。
5. `exec 1>&0`标准输出重定向，然后就能正常使用shell了。

比较玄学的是我本地一直不行但是远程是可以的，gdb跟着调也正常起shell了，有空再来研究吧。


## mmmmmmmap

有一个字节溢出可控，绕glibc的检查把heap中的chunk用`munmap`系统调用释放掉，然后就有一个fmt随便用了，改`exit_hook`即可。


## vmstack

模拟一个栈，只有几个很简单的指令：push, pop, add, sub, syscall。

保护全开没地址可用，一开始想着用`mmap`申请一块来用，后面发现控制不了太多参数，然后突然看到一个`brk`，试了一下发现会扩展至当前堆的末尾段？有点东西，然后就ORW。


