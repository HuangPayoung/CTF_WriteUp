最近刚学musl_libc的使用方法，整理几道题目到这。

~~等我有空了甚至想整个源码阅读分析~~

# 环境配置

## 源码下载与编译

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

## 添加符号

因为现在出题一般都会把符号表去掉，或者用ubuntu里面的发行版`musl_libc`，那肯定是不带符号表的，如果用自己编译好的带符号信息的libc会偏移有所不同，所以还是准备一份符号文件。

平常用惯了`glibc-all-in-one`，符号在下载的时候顺便提取了，但是现在还不支持`musl`，所以花了不少时间自己折腾一下。参考`glibc-all-in-one`里面的一些命令，通过下载ubuntu发布的一些deb文件来获取符号文件。

提取ubuntu发行版的二进制文件，这个可以照搬`glibc-all-in-one`的命令：

```
wget "http://archive.ubuntu.com/ubuntu/pool/universe/m/musl/musl_1.1.24-1_amd64.deb" 2>/dev/null -O debs/musl_1.1.24-1_amd64.deb
./extract debs/musl_1.1.24-1_amd64.deb libs/1.1.24-1_amd64
```

提取符号文件就不能照搬了，下载的是`ddeb`文件，~~其实我不知道有什么区别也懒得去看~~，但是命令差不多。

```
wget "https://launchpad.net/ubuntu/+archive/primary/+files/musl-dbgsym_1.1.24-1_amd64.ddeb" 2>/dev/null -O debs/musl-dbgsym_1.1.24-1_amd64.ddeb
mktemp -d
dpkg -x debs/musl-dbgsym_1.1.24-1_amd64.ddeb /tmp/tmp.u5lEMjD3rB/ 			# this path depend on the last command
cp -r /tmp/tmp.u5lEMjD3rB/usr/lib/debug/.build-id/ /usr/lib/debug/.build-id/
```

然后`/usr/lib/debug/`调试符号的加载路径下就有相应的符号文件了，我看到还有其他的一些调试文件，可能是根据哈希值去找的？

```
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /tmp/tmp.u5lEMjD3rB/
total 32
drwxr-xr-x  3 payoung payoung  4096 Oct 13  2019 .
drwxrwxrwt 29 root    root    20480 Nov 29 22:21 ..
drwxr-xr-x  4 payoung payoung  4096 Oct 13  2019 usr
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /tmp/tmp.u5lEMjD3rB/usr/
total 16
drwxr-xr-x 4 payoung payoung 4096 Oct 13  2019 .
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 ..
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 lib
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 share
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /tmp/tmp.u5lEMjD3rB/usr/lib/
total 12
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 .
drwxr-xr-x 4 payoung payoung 4096 Oct 13  2019 ..
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 debug
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /tmp/tmp.u5lEMjD3rB/usr/lib/debug/
total 12
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 .
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 ..
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 .build-id
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /tmp/tmp.u5lEMjD3rB/usr/lib/debug/.build-id/
total 12
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 .
drwxr-xr-x 3 payoung payoung 4096 Oct 13  2019 ..
drwxr-xr-x 2 payoung payoung 4096 Oct 13  2019 ad
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ ls -al /usr/lib/debug/.build-id/ad/
total 952
drwxr-xr-x 2 root root   4096 Nov 29 21:18 .
drwxr-xr-x 7 root root   4096 Nov 29 21:18 ..
-rw-r--r-- 1 root root 966032 Nov 29 21:18 1c27dcf0a249d73034ae447790636a4919d4ae.debug
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one$ file /usr/lib/debug/.build-id/ad/1c27dcf0a249d73034ae447790636a4919d4ae.debug 
/usr/lib/debug/.build-id/ad/1c27dcf0a249d73034ae447790636a4919d4ae.debug: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=ad1c27dcf0a249d73034ae447790636a4919d4ae, with debug_info, not stripped
```

然后用gdb调试libc或者elf就可以看到符号信息了，需要注意的是用的libc必须是上面那个用deb提取出来的二进制，可能是根据哈希值找的调试文件？我尝试用其他出题人给的一个libc也是去掉符号表但是哈希值不同，就找不到符号文件了。尝试自己手动添加符号文件也不行`pwndbg> add-symbol-file /usr/lib/debug/.build-id/ad/1c27dcf0a249d73034ae447790636a4919d4ae.debug`。

```
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64$ gdb ./libc.so 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 197 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./libc.so...
Reading symbols from /usr/lib/debug/.build-id/ad/1c27dcf0a249d73034ae447790636a4919d4ae.debug...
pwndbg> p mal
$1 = {
  binmap = 0,
  bins = {{
      lock = {0, 0},
      head = 0x0,
      tail = 0x0
    } <repeats 64 times>},
  free_lock = {0, 0}
}
pwndbg> p environ
$2 = (char **) 0x0
pwndbg> q

payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64$ gdb ./baby_musl 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 197 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./baby_musl...
(No debugging symbols found in ./baby_musl)
pwndbg> b malloc
Breakpoint 1 at 0x700
pwndbg> r
Starting program: /mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64/baby_musl 
Enter your name
aa
[1] Add
[2] Delete
[3] Edit
[4] Show
1
Enter index
0
Enter size
40

Breakpoint 1, malloc (n=40) at src/malloc/malloc.c:285
285	src/malloc/malloc.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────
 RAX  0x28
 RBX  0x0
 RCX  0x2
 RDX  0x0
 RDI  0x28
 RSI  0x0
 R8   0x3c
 R9   0x0
 R10  0x0
 R11  0x202
 R12  0x7fffffffdd38 —▸ 0x7fffffffe0fe ◂— '/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64/baby_musl'
 R13  0x7fffffffdd48 —▸ 0x7fffffffe14d ◂— 'SHELL=/bin/bash'
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdca0 —▸ 0x7fffffffdcf0 ◂— 0x1
 RSP  0x7fffffffdc68 —▸ 0x555555400941 (new+112) ◂— mov    rcx, rax
 RIP  0x7ffff7f75ed0 (malloc) ◂— endbr64 
────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x7ffff7f75ed0 <malloc>       endbr64 
   0x7ffff7f75ed4 <malloc+4>     push   r15
   0x7ffff7f75ed6 <malloc+6>     push   r14
   0x7ffff7f75ed8 <malloc+8>     push   r13
   0x7ffff7f75eda <malloc+10>    push   r12
   0x7ffff7f75edc <malloc+12>    push   rbp
   0x7ffff7f75edd <malloc+13>    push   rbx
   0x7ffff7f75ede <malloc+14>    sub    rsp, 0x38
   0x7ffff7f75ee2 <malloc+18>    mov    qword ptr [rsp + 0x18], rdi
   0x7ffff7f75ee7 <malloc+23>    lea    rdi, [rsp + 0x18]
   0x7ffff7f75eec <malloc+28>    mov    rax, qword ptr fs:[0x28]
─────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc68 —▸ 0x555555400941 (new+112) ◂— mov    rcx, rax
01:0008│     0x7fffffffdc70 ◂— 0x0
02:0010│     0x7fffffffdc78 ◂— 0x0
03:0018│     0x7fffffffdc80 ◂— 0x28 /* '(' */
04:0020│     0x7fffffffdc88 ◂— 0x4523a79c48ec0c7d
05:0028│     0x7fffffffdc90 —▸ 0x7fffffffdd38 —▸ 0x7fffffffe0fe ◂— '/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64/baby_musl'
06:0030│     0x7fffffffdc98 —▸ 0x555555400b5a (main) ◂— push   rbp
07:0038│ rbp 0x7fffffffdca0 —▸ 0x7fffffffdcf0 ◂— 0x1
───────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────
 ► f 0   0x7ffff7f75ed0 malloc
   f 1   0x555555400941 new+112
   f 2   0x555555400bfd main+163
   f 3   0x7ffff7f69c6e libc_start_main_stage2+46
   f 4   0x555555400796 _start_c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> dir /mnt/hgfs/payoung/Documents/ctf/musl/musl-1.1.24/src/malloc/
Source directories searched: /mnt/hgfs/payoung/Documents/ctf/musl/musl-1.1.24/src/malloc:$cdir:$cwd
pwndbg> si
0x00007ffff7f75ed4	285	{
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────
 RAX  0x28
 RBX  0x0
 RCX  0x2
 RDX  0x0
 RDI  0x28
 RSI  0x0
 R8   0x3c
 R9   0x0
 R10  0x0
 R11  0x202
 R12  0x7fffffffdd38 —▸ 0x7fffffffe0fe ◂— '/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64/baby_musl'
 R13  0x7fffffffdd48 —▸ 0x7fffffffe14d ◂— 'SHELL=/bin/bash'
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdca0 —▸ 0x7fffffffdcf0 ◂— 0x1
 RSP  0x7fffffffdc68 —▸ 0x555555400941 (new+112) ◂— mov    rcx, rax
*RIP  0x7ffff7f75ed4 (malloc+4) ◂— push   r15
────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
   0x7ffff7f75ed0 <malloc>       endbr64 
 ► 0x7ffff7f75ed4 <malloc+4>     push   r15
   0x7ffff7f75ed6 <malloc+6>     push   r14
   0x7ffff7f75ed8 <malloc+8>     push   r13
   0x7ffff7f75eda <malloc+10>    push   r12
   0x7ffff7f75edc <malloc+12>    push   rbp
   0x7ffff7f75edd <malloc+13>    push   rbx
   0x7ffff7f75ede <malloc+14>    sub    rsp, 0x38
   0x7ffff7f75ee2 <malloc+18>    mov    qword ptr [rsp + 0x18], rdi
   0x7ffff7f75ee7 <malloc+23>    lea    rdi, [rsp + 0x18]
   0x7ffff7f75eec <malloc+28>    mov    rax, qword ptr fs:[0x28]
─────────────────────────────────────────────────────[ SOURCE (CODE) ]─────────────────────────────────────────────────────
In file: /mnt/hgfs/payoung/Documents/ctf/musl/musl-1.1.24/src/malloc/malloc.c
   280 
   281 	__bin_chunk(split);
   282 }
   283 
   284 void *malloc(size_t n)
 ► 285 {
   286 	struct chunk *c;
   287 	int i, j;
   288 
   289 	if (adjust_size(&n) < 0) return 0;
   290 
─────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc68 —▸ 0x555555400941 (new+112) ◂— mov    rcx, rax
01:0008│     0x7fffffffdc70 ◂— 0x0
02:0010│     0x7fffffffdc78 ◂— 0x0
03:0018│     0x7fffffffdc80 ◂— 0x28 /* '(' */
04:0020│     0x7fffffffdc88 ◂— 0x4523a79c48ec0c7d
05:0028│     0x7fffffffdc90 —▸ 0x7fffffffdd38 —▸ 0x7fffffffe0fe ◂— '/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/1.1.24-1_amd64/baby_musl'
06:0030│     0x7fffffffdc98 —▸ 0x555555400b5a (main) ◂— push   rbp
07:0038│ rbp 0x7fffffffdca0 —▸ 0x7fffffffdcf0 ◂— 0x1
───────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────
 ► f 0   0x7ffff7f75ed4 malloc+4
   f 1   0x555555400941 new+112
   f 2   0x555555400bfd main+163
   f 3   0x7ffff7f69c6e libc_start_main_stage2+46
   f 4   0x555555400796 _start_c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p mal
$1 = {
  binmap = 824633720832,
  bins = {{
      lock = {0, 0},
      head = 0x0,
      tail = 0x0
    } <repeats 38 times>, {
      lock = {0, 0},
      head = 0x7ffff7ffe310,
      tail = 0x7ffff7ffe310
    }, {
      lock = {0, 0},
      head = 0x555555602070,
      tail = 0x555555605050
    }, {
      lock = {0, 0},
      head = 0x0,
      tail = 0x0
    } <repeats 24 times>},
  free_lock = {0, 0}
}
pwndbg> q
```


## 符号文件的加载分析

题外话，我在尝试寻找符号文件过程中的一些分析思考，结合本地环境我大致猜测一下gdb如何加载调试符号。

1. ubuntu2004本地自带的glibc，会去本地`/usr/lib/debug`的路径下找相关的符号文件。

```
pwndbg> show debug-file-directory
The directory where separate debug symbols are searched for is "/usr/lib/debug".
pwndbg> 
```

去该路径下找就会发现有一个和我们平时使用的`/lib/x86_64-linux-gnu/libc-2.31.so`哈希值一模一样的`libc-2.31.so`，但是居然显示有调试信息而且未除去符号表，或许我们平时没patchelf用系统自带的2.31能够有符号调试正是用的这个，但是既然有`debug_info`而且`no stripped`为啥会和`stripped`后的二进制文件保持哈希一致呢？有点想不明白。

```
payoung@ubuntu:/usr/lib/debug$ ls -al
total 20
drwxr-xr-x   5 root root 4096 Aug 19 03:40 .
drwxr-xr-x 148 root root 4096 Oct 21 19:05 ..
drwxr-xr-x   7 root root 4096 Nov 29 21:18 .build-id
drwxr-xr-x   5 root root 4096 Aug 28 02:11 lib
drwxr-xr-x   3 root root 4096 Aug 19 03:40 usr
payoung@ubuntu:/usr/lib/debug$ ls -al ./lib/
total 20
drwxr-xr-x 5 root root 4096 Aug 28 02:11 .
drwxr-xr-x 5 root root 4096 Aug 19 03:40 ..
drwxr-xr-x 2 root root 4096 Aug 28 02:11 i386-linux-gnu
drwxr-xr-x 3 root root 4096 Aug 19 03:40 libc6-prof
drwxr-xr-x 2 root root 4096 Aug 19 03:40 x86_64-linux-gnu
payoung@ubuntu:/usr/lib/debug$ ls -al ./lib/x86_64-linux-gnu/
total 28012
drwxr-xr-x 2 root root     4096 Aug 19 03:40 .
drwxr-xr-x 5 root root     4096 Aug 28 02:11 ..
-rwxr-xr-x 1 root root  1409464 Dec 16  2020 ld-2.31.so
-rw-r--r-- 1 root root   131600 Dec 16  2020 libanl-2.31.so
-rw-r--r-- 1 root root    22656 Dec 16  2020 libBrokenLocale-2.31.so
-rwxr-xr-x 1 root root 17371928 Dec 16  2020 libc-2.31.so
-rw-r--r-- 1 root root   241048 Dec 16  2020 libdl-2.31.so
-rw-r--r-- 1 root root  4611328 Dec 16  2020 libm-2.31.so
-rw-r--r-- 1 root root    56248 Dec 16  2020 libmemusage.so
-rw-r--r-- 1 root root   707616 Dec 16  2020 libmvec-2.31.so
-rw-r--r-- 1 root root   749248 Dec 16  2020 libnsl-2.31.so
-rw-r--r-- 1 root root   199992 Dec 16  2020 libnss_compat-2.31.so
-rw-r--r-- 1 root root   140104 Dec 16  2020 libnss_dns-2.31.so
-rw-r--r-- 1 root root   389448 Dec 16  2020 libnss_files-2.31.so
-rw-r--r-- 1 root root   120200 Dec 16  2020 libnss_hesiod-2.31.so
-rw-r--r-- 1 root root   407744 Dec 16  2020 libnss_nis-2.31.so
-rw-r--r-- 1 root root   491336 Dec 16  2020 libnss_nisplus-2.31.so
-rw-r--r-- 1 root root    10232 Dec 16  2020 libpcprofile.so
-rw-r--r-- 1 root root   511336 Dec 16  2020 libresolv-2.31.so
-rw-r--r-- 1 root root   345200 Dec 16  2020 librt-2.31.so
-rw-r--r-- 1 root root    89240 Dec 16  2020 libSegFault.so
-rw-r--r-- 1 root root   595808 Dec 16  2020 libthread_db-1.0.so
-rw-r--r-- 1 root root    34976 Dec 16  2020 libutil-2.31.so
payoung@ubuntu:/usr/lib/debug$ file ./lib/x86_64-linux-gnu/libc-2.31.so 
./lib/x86_64-linux-gnu/libc-2.31.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter *empty*, BuildID[sha1]=099b9225bcb0d019d9d60884be583eb31bb5f44e, for GNU/Linux 3.2.0, with debug_info, not stripped
payoung@ubuntu:/usr/lib/debug$ file /lib/x86_64-linux-gnu/libc-2.31.so 
/lib/x86_64-linux-gnu/libc-2.31.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=099b9225bcb0d019d9d60884be583eb31bb5f44e, for GNU/Linux 3.2.0, stripped
```

2. `glibc-all-in-one`里面的libc如何加载符号文件：

```
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ gdb ./libc-2.23.so 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 197 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./libc-2.23.so...
Reading symbols from /mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/.debug/libc-2.23.so...
pwndbg> 
```

可以看到是用的libc当前目录下的`.debug`文件夹，查看一下发现和本地`/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.31.so`的形式类似，也是加了调试信息和符号表，但是哈希值保持不变。

```
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ file .debug/libc-2.23.so 
.debug/libc-2.23.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter *empty*, BuildID[sha1]=30773be8cf5bfed9d910c8473dd44eaab2e705ab, for GNU/Linux 2.6.32, with debug_info, not stripped
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ file libc-2.23.so 
libc-2.23.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=30773be8cf5bfed9d910c8473dd44eaab2e705ab, for GNU/Linux 2.6.32, stripped
```

3. 康康`musl libc`。

加载符号文件的方式好像略有不同，我现在本地的环境因为做题现在`musl libc`版本是1.2.2，可以看到和本地的glibc略有不同，不过也是在`/usr/lib/debug/`这个路径下找，然后`./build-id/`路径下有几个文件夹，看了一下似乎是libc的sha1哈希值前两位（这个不怕冲突吗？哈希碰撞个前两位那不是轻轻松松？），然后文件夹下就是调试的`xx.debug`符号文件了，（名字又是一个奇怪的哈希值？），可以看到和glibc一样也是多了调试信息和符号表，而哈希值保持不变，试了一下执行直接报`Segmentation fault (core dumped)`，看来还是有所不同的，正常的`musl libc`执行应该输出提示信息才对。我也是照着这个配了一个`musl 1.1.24`的调试符号文件。

```
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ gdb /lib/x86_64-linux-musl/libc.so 
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 197 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from /lib/x86_64-linux-musl/libc.so...
Reading symbols from /usr/lib/debug/.build-id/3a/26f086e73e894a846741a206dc1cb72d639ee7.debug...
pwndbg> q
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ file /lib/x86_64-linux-musl/libc.so 
/lib/x86_64-linux-musl/libc.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=3a26f086e73e894a846741a206dc1cb72d639ee7, stripped
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ file /usr/lib/debug/.build-id/3a/26f086e73e894a846741a206dc1cb72d639ee7.debug
/usr/lib/debug/.build-id/3a/26f086e73e894a846741a206dc1cb72d639ee7.debug: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=3a26f086e73e894a846741a206dc1cb72d639ee7, with debug_info, not stripped
payoung@ubuntu:/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64$ /usr/lib/debug/.build-id/3a/26f086e73e894a846741a206dc1cb72d639ee7.debug
Segmentation fault (core dumped)
```

4. 分析一下平时用的`glibc-all-in-one`。

`update_list`使用python写的脚本，用正则表达式匹配，去ubuntu官方源和清华源拖相应版本libc以及调试文件的deb包。

```
#!/usr/bin/python
import re
import requests

common_url = 'https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/'
# url = 'http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/'
old_url = 'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/'


def get_list(url, arch):
    content = str(requests.get(url).content)
    return re.findall('libc6_(2\.[0-9][0-9]-[0-9]ubuntu[0-9\.]*_{}).deb'.format(arch), content)


common_list = get_list(common_url, 'amd64')
common_list += get_list(common_url, 'i386')

with open('list', 'w') as f:
    for l in sorted(set(common_list)):
        f.write(l + '\n')

print('[+] Common list has been save to "list"')

old_list = get_list(old_url, 'amd64')
old_list += get_list(old_url, 'i386')

with open('old_list', 'w') as f:
    for l in sorted(set(old_list)):
        f.write(l + '\n')

print('[+] Old-release list has been save to "old_list"')
```

`download`和`download_old`脚本类似只是源不同，这里来看`download`，核心在`download_single`函数，从源下载libc二进制的deb以及调试符号文件的deb。

```
#!/bin/bash
cd "$(dirname "$0")"
if [ ! -d "libs" ]; then
    mkdir libs
fi

if [ ! -d "debs" ];  then
    mkdir debs
fi

SOURCE="https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc"
# Use the source below if you feel slow, or change it on your own.
# SOURCE="http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/"

LIBC_PREFIX="libc6_"
LIBC_DBG_PREFIX="libc6-dbg_"

die() {
  echo >&2 $1
  exit 1
}

usage() {
  echo >&2 "Usage: $0 id"
  exit 2
}

download_single() {
  local id=$1
  local deb_name=$LIBC_PREFIX$id.deb
  local dbg_name=$LIBC_DBG_PREFIX$id.deb
  echo "Getting $id"
  if [ -d "libs/$id" ]; then
    die "  --> Downloaded before. Remove it to download again."
  fi

  # download binary package
  local url="$SOURCE/$deb_name"
  echo "  -> Location: $url"
  echo "  -> Downloading libc binary package"
  wget "$url" 2>/dev/null -O debs/$deb_name || die "Failed to download package from $url"
  echo "  -> Extracting libc binary package"

  mkdir libs/$id
  ./extract debs/$deb_name libs/$id
  echo "  -> Package saved to libs/$id"

  # download debug info package
  local url="$SOURCE/$dbg_name"
  echo "  -> Location: $url"
  echo "  -> Downloading libc debug package"
  wget "$url" 2>/dev/null -O debs/$dbg_name || die "Failed to download package from $url"
  echo "  -> Extracting libc debug package"

  mkdir libs/$id/.debug
  ./extract debs/$dbg_name libs/$id/.debug
  echo "  -> Package saved to libs/$id/.debug"
}

if [[ $# != 1 ]]; then
  usage
fi
download_single "$1"
```

最后用`extract`脚本提取两个包，其中调试的内容保存在`.debug`目录下。

```
#!/bin/bash
cd "$(dirname "$0")"

die() {
  echo >&2 $1
  exit 1
}

usage() {
  echo -e >&2 "Usage: $0 deb output"
  exit 2
}

extract() {
    local deb=$1
    local out=$2
    if [ ! -d "$out" ]; then
        mkdir $out
    fi
    local tmp=`mktemp -d`
    dpkg -x $deb $tmp || die "dpkg failed"

    cp -rP $tmp/lib/*/* $out 2>/dev/null || cp -rP $tmp/lib32/* $out 2>/dev/null \
      || cp -rP $tmp/usr/lib/debug/lib/*/* $out 2>/dev/null || cp -rP $tmp/usr/lib/debug/lib32/* $out 2>/dev/null \
      || die "Failed to save. Check it manually $tmp"
    
    rm -rf $tmp
}

if [[ $# -ne 2 ]]; then
    usage
fi

extract "$1" "$2"

```

`build`脚本则是用来将源码编译成二进制文件，暂时没用上就没有仔细看了，大致看也不是很复杂，以后有用上再说。


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
3. 利用queue函数把伪造的meta放入__malloc_context的active数组当中，下次申请即可拿到。
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


## 0ctf_finals_2021_BabaHeap

打比赛的时候太菜了不会做，放题也有点晚，睡完起来没时间做了，参考[r3kapig](https://r3kapig.com/writeup/20211011-0ctf-finals/)师傅的博客复现。

### 攻击思路

1. 分别释放0x1c0和0x120小的堆块到mal数组当中，选择这个大小的原因是`&mal.bins[8] == 0x7ffff7ffbb00; &mal.bins[13] == 0x7ffff7ffbb78;`。
2. 利用UAF漏洞修改0x1c0堆块的next域，利用修改时会在末尾补`\x00`的特性，刚好partial_write使得next指向`&mal.bins[8]`。
3. 申请0x1c0的堆块先拿回第一次释放的堆，由于unbin就会在`&mal.bins[13].head`写入`&mal.bins[8]`，再次申请0x1c0的堆块就能拿到`mal.bins[8]`区域的fake_chunk。之前释放0x120大小的堆块是为了现在拿fake_chunk时unbin函数的双链表操作，保证next和prev域指向的区域可写。
4. 拿到mal上的堆块就很好做了，释放该区域的堆块，就能泄露heap进而泄露libc_base。
5. 修改mal上的链表来任意地址分配，和上面的思路类似，申请`__stdin_FILE`对应的fake_chunk，同样要提前布置next和prev可写指针。
6. 拿到`__stdin_FILE`结构体后伪造IO结构体，然后退出main函数，在exit函数中劫持控制流进行栈迁移并ORW。


## n1ctf_2021_House_of_tataru

太菜了做不出来，参考[Super Guesser](https://kileak.github.io/ctf/2021/n1ctf21-tataru/)博客复现的，这老哥还说他从没做过musl，太牛了。

另外还参考了[r3kapig](https://r3kapig.com/writeup/20211122-n1ctf/#house_of_tataru)（没有侧信道直接爆破）和[官方wp](https://github.com/Nu1LCTF/n1ctf-2021/tree/main/Pwn/house_of_tataru)，不过我觉得官方的作法稍微麻烦，另外两位都是改已`freed`的`meta->mem`字段，这样可以直接过`calloc`的检查。

### 程序功能

```
struct note
{
	char *buffer;
	size_t size;
	size_t offset;
}
```

bss段上`notelist`保存两个这种结构体。

菜单题：
1. 添加功能，可申请`0x1000`以下大小的堆块，以calloc方式申请，然后写入申请长度。注意这里存在漏洞，如果设置的size大于`0x1000`，只会更新`size`字段而不会改指针。
2. 将`size`拷贝至`offset`字段，结合功能1其实就可以随便设置这两个字段，不过需要0x1000以上。
3. 写功能，可以从`noteptr->buffer[offset]`写至`noteptr->buffer[size]`，但是有个奇怪的检查，写的地址不能超过`libc`的基址，也就是elf和heap这两段空间。另外要注意的是`read`函数如果读的是未分配的内存空间，其实并不会崩溃，只会返回`-1`表示失败，而程序针对此处的检查也就打印出`failed`字符串而不是退出，所以可以用这个特性来侧信道。
4. 读功能，可以从`noteptr->buffer[offset]`开始读出一个字符串，有零字符截断，检查同上也不能读`libc`基址以后的空间。

### 攻击思路

1. 利用bss段上一些存在的已经被freed掉的group，先申请bss段上的堆块，然后通过越界读`group->meta`字段可以泄露堆地址。
2. 侧信道泄露`bss段`与`heap段`之间的距离：写失败并不会崩溃而是打印字符串`failed`，所以可以利用这个特性来判断，据r3的师傅描述，开启ASLR后`bss段`与`heap段`之间的距离为`1-0x2000`页，他们比较粗暴直接嗯爆破，侧信道的话则从1页开始测试然后逐渐增加，直至写成功那一次就不会返回`failed`字符串了。
3. gusser队伍的师傅不太熟musl，按他们的描述使用动态调的方法来破坏musl的分配：他们先分配新大小（0x30）的堆块，然后发现这个堆块地址会保存在`heap段`上，据我调试应该是被释放掉的`meta->mem`，这个`meta`管理的`group`里面的堆块全都释放的（或许是程序刚开始bss段上这个group里面的堆块没被申请），所以利用越界写先提前写改掉`meta->mem`字段，然后申请0x30大小的堆块就任意能申请到我们想要的内存空间。
4. 用上述的方法申请bss段上的`notelist`地址，然后就能用3/4任意读写（当然还是要在libc地址之前），写个read函数got表来泄露libc基址。
5. 重复上述的方法，申请libc里面的`head`变量，因为3/4都有检查，只能通过1的申请功能来任意申请从而任意写。改掉`head`变量后退出`main`函数，然后就能在`exit`函数里面触发`exit_hook`。
6. 劫持控制流后用`longjmp`函数的gadgets来栈劫持至bss段上提前布置的ROP链，ORW读flag。


# 参考链接

[musl 1.1.24 出题人角度解析](https://www.anquanke.com/post/id/202253#h2-9)

[musl 1.1.24 exit劫持控制流](https://niebelungen-d.top/2021/08/22/Musl-libc-Pwn-Learning/)

[从musl libc 1.1.24到1.2.2 学习pwn姿势](https://www.anquanke.com/post/id/253566)

[musl 1.2.2 源码审计](https://www.anquanke.com/post/id/241101)

[musl 1.2.2 漏洞利用](https://www.anquanke.com/post/id/241104)

[musl-1.2.x堆部分源码分析](https://www.anquanke.com/post/id/246929)

[新版musl-libc malloc源码分析与调试](https://www.anquanke.com/post/id/252293#h2-0)

[新版musl libc 浅析](http://pzhxbz.cn/?p=172)

[2021强网杯easyheap](https://www.anquanke.com/post/id/248411)
