# carbon

### 简介

* musl libc 1.1.24 堆漏洞利用
* 允许堆溢出 0x50 字节一次。

### 保护

1. 开启 PIE 以外的所有保护（Full RELRO、Canary），已 strip。  
（若开启 PIE，原 writeup 中绕过保护4的方法失效）
2. 0 <= size <= 0x80, 0 <= idx <= 15
3. 只能 view 一次。
4. 仅当 malloc 返回的指针为<del> NULL 或者 </del>0xbadbeef 时调用`exit`函数，其余均为 crash。  
(当`binmap = 0`、`brk = -1`、`mmap_step = 0x33`时，malloc 返回 NULL）
5. LIST 位于 mmap 内存。
6. 清空已释放指针的地址，防止 use after free。

### 注意
master 分支存放原题目源码，fix 分支存放修复非预期解后的题目源码。
