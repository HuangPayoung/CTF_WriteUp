64位下堆题，开启NX，canary，FULL RELRO保护机制，没开启PIE，增删查三项功能。漏洞点在于删除时候没有清空指针，导致UAF漏洞。

攻击思路：
1. 将控制堆块修改成got表，利用UAF泄露libc基址。
2. fastbins攻击，在__malloc_hook附近伪造fake_chunk，然后用realloc调整栈上的变量。
